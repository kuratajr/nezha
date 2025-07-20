package controller

import (
	"slices"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"bytes"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/tidwall/gjson"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/utils"
	"github.com/nezhahq/nezha/service/singleton"
)

func getRedirectURL(c *gin.Context) string {
	scheme := "http://"
	referer := c.Request.Referer()
	if forwardedProto := c.Request.Header.Get("X-Forwarded-Proto"); forwardedProto == "https" || strings.HasPrefix(referer, "https://") {
		scheme = "https://"
	}
	return scheme + c.Request.Host + "/api/v1/oauth2/callback"
}

// @Summary Get Oauth2 Redirect URL
// @Description Get Oauth2 Redirect URL
// @Produce json
// @Param provider path string true "provider"
// @Param type query int false "type" Enums(1, 2) default(1)
// @Success 200 {object} model.Oauth2LoginResponse
// @Router /api/v1/oauth2/{provider} [get]
func oauth2redirect(c *gin.Context) (*model.Oauth2LoginResponse, error) {
	provider := c.Param("provider")
	if provider == "" {
		return nil, singleton.Localizer.ErrorT("provider is required")
	}

	rTypeInt, err := strconv.ParseUint(c.Query("type"), 10, 8)
	if err != nil {
		return nil, err
	}

	o2confRaw, has := singleton.Conf.Oauth2[provider]
	if !has {
		return nil, singleton.Localizer.ErrorT("provider not found")
	}
	redirectURL := getRedirectURL(c)
	o2conf := o2confRaw.Setup(redirectURL)

	randomString, err := utils.GenerateRandomString(32)
	if err != nil {
		return nil, err
	}
	state, stateKey := randomString[:16], randomString[16:]
	singleton.Cache.Set(fmt.Sprintf("%s%s", model.CacheKeyOauth2State, stateKey), &model.Oauth2State{
		Action:      model.Oauth2LoginType(rTypeInt),
		Provider:    provider,
		State:       state,
		RedirectURL: redirectURL,
	}, cache.DefaultExpiration)

	// url := o2conf.AuthCodeURL(state, oauth2.AccessTypeOnline)
	url := o2conf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
	c.SetCookie("nz-o2s", stateKey, 60*5, "", "", false, false)

	return &model.Oauth2LoginResponse{Redirect: url}, nil
}

// @Summary Unbind Oauth2
// @Description Unbind Oauth2
// @Accept json
// @Produce json
// @Param provider path string true "provider"
// @Success 200 {object} any
// @Router /api/v1/oauth2/{provider}/unbind [post]
func unbindOauth2(c *gin.Context) (any, error) {
	provider := c.Param("provider")
	if provider == "" {
		return nil, singleton.Localizer.ErrorT("provider is required")
	}
	_, has := singleton.Conf.Oauth2[provider]
	if !has {
		return nil, singleton.Localizer.ErrorT("provider not found")
	}
	provider = strings.ToLower(provider)

	u := c.MustGet(model.CtxKeyAuthorizedUser).(*model.User)
	query := singleton.DB.Where("provider = ? AND user_id = ?", provider, u.ID)

	var bindCount int64
	if err := query.Model(&model.Oauth2Bind{}).Count(&bindCount).Error; err != nil {
		return nil, newGormError("%v", err)
	}

	if bindCount < 2 && u.RejectPassword {
		return nil, singleton.Localizer.ErrorT("operation not permitted")
	}

	if err := query.Delete(&model.Oauth2Bind{}).Error; err != nil {
		return nil, newGormError("%v", err)
	}

	return nil, nil
}

// @Summary Oauth2 Callback
// @Description Oauth2 Callback
// @Accept json
// @Produce json
// @Param state query string true "state"
// @Param code query string true "code"
// @Success 200 {object} model.CommonResponse[any]
// @Router /api/v1/oauth2/callback [get]
func oauth2callback(jwtConfig *jwt.GinJWTMiddleware) func(c *gin.Context) (any, error) {
	return func(c *gin.Context) (any, error) {
		callbackData := &model.Oauth2Callback{
			State: c.Query("state"),
			Code:  c.Query("code"),
		}

		state, err := verifyState(c, callbackData.State)
		if err != nil {
			return nil, err
		}

		o2confRaw, has := singleton.Conf.Oauth2[state.Provider]
		if !has {
			return nil, singleton.Localizer.ErrorT("provider not found")
		}

		realip := c.GetString(model.CtxKeyRealIPStr)
		if callbackData.Code == "" {
			model.BlockIP(singleton.DB, realip, model.WAFBlockReasonTypeBruteForceOauth2, model.BlockIDToken)
			return nil, singleton.Localizer.ErrorT("code is required")
		}

		openId, accessToken, refreshToken, expiry, err := exchangeOpenId(c, o2confRaw, callbackData, state.RedirectURL)
		if err != nil {
			model.BlockIP(singleton.DB, realip, model.WAFBlockReasonTypeBruteForceOauth2, model.BlockIDToken)
			return nil, err
		}

		var bind model.Oauth2Bind
		state.Provider = strings.ToLower(state.Provider)
		switch state.Action {
		case model.RTypeBind:
			u, authorized := c.Get(model.CtxKeyAuthorizedUser)
			if !authorized {
				return nil, singleton.Localizer.ErrorT("unauthorized")
			}
			user := u.(*model.User)

			result := singleton.DB.Where("provider = ? AND open_id = ?", state.Provider, openId).Limit(1).Find(&bind)
			if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
				return nil, newGormError("%v", result.Error)
			}
			bind.UserID = user.ID
			bind.Provider = state.Provider
			bind.OpenID = openId
			bind.AccessToken = accessToken
			bind.RefreshToken = refreshToken
			bind.TokenExpiry = expiry

			if result.Error == gorm.ErrRecordNotFound {
				result = singleton.DB.Create(&bind)
			} else {
				result = singleton.DB.Save(&bind)
			}
			if result.Error != nil {
				return nil, newGormError("%v", result.Error)
			}
		default:
			if err := singleton.DB.Where("provider = ? AND open_id = ?", state.Provider, openId).First(&bind).Error; err != nil {
				return nil, singleton.Localizer.ErrorT("oauth2 user not binded yet")
			}
			bind.AccessToken = accessToken
			bind.RefreshToken = refreshToken
			bind.TokenExpiry = expiry
			singleton.DB.Save(&bind)
		}

		tokenString, _, err := jwtConfig.TokenGenerator(fmt.Sprintf("%d", bind.UserID))
		if err != nil {
			return nil, err
		}

		jwtConfig.SetCookie(c, tokenString)
		c.Redirect(http.StatusFound, utils.IfOr(state.Action == model.RTypeBind, "/dashboard/profile?oauth2=true", "/dashboard/login?oauth2=true"))

		return nil, errNoop
	}
}

func exchangeOpenId(c *gin.Context, o2confRaw *model.Oauth2Config,
	callbackData *model.Oauth2Callback, redirectURL string) (openID, accessToken, refreshToken string, expiry int64, err error) {
	o2conf := o2confRaw.Setup(redirectURL)

	otk, err := o2conf.Exchange(c, callbackData.Code)
	if err != nil {
		return "", "", "", 0, err
	}
	oauth2client := o2conf.Client(c, otk)
	resp, err := oauth2client.Get(o2confRaw.UserInfoURL)
	if err != nil {
		return "", "", "", 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", 0, err
	}
	openID = gjson.GetBytes(body, o2confRaw.UserIDPath).String()
	accessToken = otk.AccessToken
	refreshToken = otk.RefreshToken
	expiry = otk.Expiry.Unix()
	return openID, accessToken, refreshToken, expiry, nil
}

func verifyState(c *gin.Context, state string) (*model.Oauth2State, error) {
	// 验证登录跳转时的 State
	stateKey, err := c.Cookie("nz-o2s")
	if err != nil {
		return nil, singleton.Localizer.ErrorT("invalid state key")
	}

	cacheKey := fmt.Sprintf("%s%s", model.CacheKeyOauth2State, stateKey)
	istate, ok := singleton.Cache.Get(cacheKey)
	if !ok {
		return nil, singleton.Localizer.ErrorT("invalid state key")
	}

	oauth2State, ok := istate.(*model.Oauth2State)
	if !ok || oauth2State.State != state {
		return nil, singleton.Localizer.ErrorT("invalid state key")
	}

	return oauth2State, nil
}

//API: POST /api/v1/server/:action/port
func openPortCloudflared(c *gin.Context) (any, error) {
	cloudflare_token := singleton.Conf.Cloudflared.Token
	accountid := singleton.Conf.Cloudflared.AccountID
	tunnelid := singleton.Conf.Cloudflared.TunnelID
	tailscale_token := singleton.Conf.Tailscaled.Token
	dns := singleton.Conf.Tailscaled.Dns

	action := c.Param("action")

	type PortRequest struct {
		Servers []uint64 `json:"servers"`
		Ports   []int    `json:"ports"`
	}
	type IngressConfig struct {
		Hostname string `json:"hostname"`
		Service  string `json:"service"`
	}
	type ServerResult struct {
		ServerID uint64          `json:"server_id"`
		Hostname string          `json:"hostname"`
		IP       string          `json:"ip,omitempty"`
		Ports    []int           `json:"ports"`
		Ingress  []IngressConfig `json:"ingress"`
		Status   []string        `json:"status"`
		Error    string          `json:"error,omitempty"`
	}

	var req PortRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return nil, err
	}
	if len(req.Servers) == 0 {
		return nil, singleton.Localizer.ErrorT("servers list is required")
	}
	if len(req.Ports) == 0 {
		return nil, singleton.Localizer.ErrorT("ports list is required")
	}
	if !singleton.ServerShared.CheckPermission(c, slices.Values(req.Servers)) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}

	results := make([]ServerResult, 0, len(req.Servers))

	for _, serverID := range req.Servers {
		var s model.Server
		if err := singleton.DB.First(&s, serverID).Error; err != nil {
			results = append(results, ServerResult{
				ServerID: serverID,
				Ports:    req.Ports,
				Error:    fmt.Sprintf("server id %d does not exist", serverID),
			})
			continue
		}

		hostname := s.ConfigDetail.Name
		if parts := strings.Split(s.ConfigDetail.Name, "/"); len(parts) > 0 {
			hostname = parts[len(parts)-1]
		}

		var ip string
		if device, err := callTailscaleAPI(dns, tailscale_token, hostname); err == nil {
			if addrs, ok := device["addresses"].([]interface{}); ok && len(addrs) > 0 {
				if ipstr, ok := addrs[0].(string); ok {
					ip = ipstr
				}
			}
		}

		allconfig, err := callCloudflareAPI(cloudflare_token, accountid, tunnelid, "list", nil)
		if err != nil {
			results = append(results, ServerResult{
				ServerID: serverID,
				Hostname: hostname,
				IP:       ip,
				Ports:    req.Ports,
				Error:    "Cloudflare get config: " + err.Error(),
			})
			continue
		}

		var cfResp map[string]interface{}
		if err := json.Unmarshal(allconfig, &cfResp); err != nil {
			results = append(results, ServerResult{
				ServerID: serverID,
				Hostname: hostname,
				IP:       ip,
				Ports:    req.Ports,
				Error:    "Cloudflare parse config: " + err.Error(),
			})
			continue
		}

		result, ok := cfResp["result"].(map[string]interface{})
		if !ok {
			results = append(results, ServerResult{
				ServerID: serverID,
				Hostname: hostname,
				IP:       ip,
				Ports:    req.Ports,
				Error:    "Cloudflare result format invalid",
			})
			continue
		}

		config, ok := result["config"].(map[string]interface{})
		if !ok {
			config = make(map[string]interface{})
		}
		ingressList, _ := config["ingress"].([]interface{})
		ingressListNew := ingressList

		if action == "list" {
			filtered := []IngressConfig{}
			for _, item := range ingressList {
				if m, ok := item.(map[string]interface{}); ok {
					if h, ok := m["hostname"].(string); ok && strings.Contains(h, hostname) {
						svc, _ := m["service"].(string)
						filtered = append(filtered, IngressConfig{
							Hostname: h,
							Service:  svc,
						})
					}
				}
			}
			return filtered, nil
		}

		ingress := make([]IngressConfig, 0, len(req.Ports))
		status := make([]string, 0, len(req.Ports))
		ingressExisted := make(map[string]int)
		needUpdate := false

		for idx, item := range ingressListNew {
			if m, ok := item.(map[string]interface{}); ok {
				if h, ok := m["hostname"].(string); ok {
					ingressExisted[h] = idx
				}
			}
		}

		newHostsSet := make(map[string]struct{})
		for _, port := range req.Ports {
			newHost := fmt.Sprintf("%d-%s.googleidx.click", port, hostname)
			newService := fmt.Sprintf("http://%s:%d", ip, port)

			ingress = append(ingress, IngressConfig{
				Hostname: newHost,
				Service:  newService,
			})
			newHostsSet[newHost] = struct{}{}

			if idx, ok := ingressExisted[newHost]; ok {
				if m, ok := ingressListNew[idx].(map[string]interface{}); ok {
					oldService, _ := m["service"].(string)
					if oldService != newService {
						m["service"] = newService
						ingressListNew[idx] = m
						status = append(status, "đã cập nhật service")
						needUpdate = true
					} else {
						status = append(status, "tồn tại (không đổi)")
					}
				}
			} else {
				entry := map[string]interface{}{
					"hostname": newHost,
					"service":  newService,
				}
				ingressListNew = append(ingressListNew, entry)
				status = append(status, "đã thêm mới")
				needUpdate = true
			}
		}

		// ✅ Xử lý xóa rule cũ và đảm bảo default rule nằm cuối
		cleanedIngressList := make([]interface{}, 0)
		var defaultRule map[string]interface{}

		for _, item := range ingressListNew {
			if m, ok := item.(map[string]interface{}); ok {
				h, _ := m["hostname"].(string)
				svc, _ := m["service"].(string)

				// Nếu là default rule thì giữ lại sau
				if h == "" && svc == "http_status:404" {
					defaultRule = m
					continue
				}

				// Nếu không phải rule của server hiện tại thì giữ lại
				if !strings.Contains(h, hostname) {
					cleanedIngressList = append(cleanedIngressList, m)
					continue
				}

				// Nếu là rule của server hiện tại mà vẫn cần dùng → giữ lại
				if _, exists := newHostsSet[h]; exists {
					cleanedIngressList = append(cleanedIngressList, m)
				} else {
					status = append(status, fmt.Sprintf("đã xóa rule cũ %s", h))
					needUpdate = true
				}
			}
		}

		// Append default rule vào cuối cùng
		if defaultRule != nil {
			cleanedIngressList = append(cleanedIngressList, defaultRule)
		}
		ingressListNew = cleanedIngressList

		var cfErr error
		if needUpdate {
			cfPayload := map[string]interface{}{
				"config": map[string]interface{}{
					"ingress": ingressListNew,
				},
			}
			payloadBytes, _ := json.Marshal(cfPayload)
			_, cfErr = callCloudflareAPI(cloudflare_token, accountid, tunnelid, "create", bytes.NewReader(payloadBytes))
		}

		resultObj := ServerResult{
			ServerID: serverID,
			Hostname: hostname,
			IP:       ip,
			Ports:    req.Ports,
			Ingress:  ingress,
			Status:   status,
		}
		if cfErr != nil {
			resultObj.Error = "Cloudflare: " + cfErr.Error()
		}
		results = append(results, resultObj)
	}

	return results, nil
}


//call API tailscale
func callTailscaleAPI(tailnet, apiKey, targetHostname string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/devices", tailnet)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error calling Tailscale API: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Tailscale API error (status %d): %s", resp.StatusCode, string(body))
	}
	
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}
	
	// Find device by hostname
	devices, ok := result["devices"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("devices field not found in response")
	}
	
	var targetDevice map[string]interface{}
	for _, device := range devices {
		if deviceMap, ok := device.(map[string]interface{}); ok {
			if hostname, ok := deviceMap["hostname"].(string); ok && hostname == targetHostname {
				targetDevice = deviceMap
				break
			}
		}
	}
	
	if targetDevice == nil {
		return nil, fmt.Errorf("device with hostname '%s' not found", targetHostname)
	}
	
	return targetDevice, nil
}
//call API cloudflared
func callCloudflareAPI(cloudflare_token, accountid, tunnelid string, action string, body io.Reader) ([]byte, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/cfd_tunnel/%s/configurations", accountid, tunnelid)
	method := "GET"
	if action == "create" {
		method = "PUT"		
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cloudflare_token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Cloudflare API error (status %d): %s", resp.StatusCode, string(responseBody))
	}

	return responseBody, nil
}
//API: GET /api/v1/oauth2/:provider/list
func updateWorkstationList(c *gin.Context) (any, error) {
	provider := strings.ToLower(c.Param("provider"))
    if provider != "google" {
        return nil, singleton.Localizer.ErrorT("only support google provider")
    }

	var servers []uint64
	if err := c.ShouldBindJSON(&servers); err != nil {
		return nil, err
	}

	if !singleton.ServerShared.CheckPermission(c, slices.Values(servers)) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}

	u := c.MustGet(model.CtxKeyAuthorizedUser).(*model.User)
	var bind model.Oauth2Bind
	err := singleton.DB.Where("provider = ? AND user_id = ?", provider, u.ID).First(&bind).Error
	if err != nil {
		return nil, singleton.Localizer.ErrorT("oauth2 not binded")
	}
	
	// Lấy clientID, clientSecret từ config
	conf, ok := singleton.Conf.Oauth2[provider]
	if !ok {
		return nil, singleton.Localizer.ErrorT("provider config not found")
	}

	// --- Sử dụng thư viện oauth2 để tự động refresh token ---
	importCtx := context.Background()
	token := &oauth2.Token{
		AccessToken:  bind.AccessToken,
		RefreshToken: bind.RefreshToken,
		Expiry:       time.Unix(bind.TokenExpiry, 0),
	}
	oauthConf := &oauth2.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		Endpoint:     google.Endpoint,
	}
	tokenSource := oauthConf.TokenSource(importCtx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, singleton.Localizer.ErrorT("refresh token failed: "+err.Error())
	}
	// Nếu token mới khác token cũ, lưu lại vào DB
	if newToken.AccessToken != bind.AccessToken {
		bind.AccessToken = newToken.AccessToken
		bind.TokenExpiry = newToken.Expiry.Unix()
		singleton.DB.Save(&bind)
	}

	//get server list from bithub
	serverList, err := getServerListFromBithub()
	if err != nil {
		return nil, singleton.Localizer.ErrorT("get server list from bithub failed: "+err.Error())
	}

	// Parse lại kiểu dữ liệu serverList
	serverMap, ok := serverList.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("serverList is not a map")
	}

	// Tạo map uuid -> info
	uuidToInfo := make(map[string]map[string]interface{})
	for uuid, v := range serverMap {
		m, ok := v.(map[string]interface{})
		if ok {
			uuidToInfo[uuid] = m
		}
	}

	// update server list
	const batchSize = 20
	var updatedServers []model.Server
	var mu sync.Mutex

	for i := 0; i < len(servers); i += batchSize {
		end := i + batchSize
		if end > len(servers) {
			end = len(servers)
		}
		batch := servers[i:end]

		var dbServers []model.Server
		if err := singleton.DB.Where("id IN ?", batch).Find(&dbServers).Error; err != nil {
			fmt.Println("[ERROR] DB batch:", err)
			continue
		}

		var wg sync.WaitGroup
		for idx := range dbServers {
			wg.Add(1)
			go func(dbServer *model.Server) {
				defer wg.Done()
				var zone, projectid, clusterid, workstationid, username, workspaceid string
				if info, found := uuidToInfo[dbServer.UUID]; found {
					if name, ok := info["name"].(string); ok {
						workstationid	= name
					}
					if v, ok := info["zone"].(string); ok {
						dbServer.Zone = v
						zone = v
					}
					if v, ok := info["project_id"].(string); ok {
						dbServer.ProjectID = v
						projectid = v
					}
					if v, ok := info["cluster_id"].(string); ok {
						dbServer.ClusterID = v
						clusterid = v
					}

					if v, ok := info["username"].(string); ok {
						username = strings.ToUpper(v)
					}
					if v, ok := info["workspace"].(string); ok {
						workspaceid = v
					}
					
					if username != "" && workspaceid != "" {
						dbServer.Name = fmt.Sprintf("[%s] - %s", username, workspaceid)
					}
	
					if zone != "" && projectid != "" && clusterid != "" && workstationid != "" {
						detailBody, err := callWorkstationDetailAPI(c, newToken.AccessToken, zone, projectid, clusterid, workstationid)
						if err == nil {
							var result map[string]interface{}
							if err := json.Unmarshal(detailBody, &result); err == nil {
								if name, ok := result["name"].(string); ok {
									dbServer.ConfigDetail.Name = name
								}
								if displayName, ok := result["displayName"].(string); ok {
									dbServer.ConfigDetail.DisplayName = displayName
								}
								if uid, ok := result["uid"].(string); ok {
									dbServer.ConfigDetail.Uid = uid
								}
								if createTime, ok := result["createTime"].(string); ok {
									dbServer.ConfigDetail.CreateTime = createTime
								}
								if updateTime, ok := result["updateTime"].(string); ok {
									dbServer.ConfigDetail.UpdateTime = updateTime
								}
								if etag, ok := result["etag"].(string); ok {
									dbServer.ConfigDetail.Etag = etag
								}
								if state, ok := result["state"].(string); ok {
									dbServer.ConfigDetail.State = state
								}
								if host, ok := result["host"].(string); ok {
									dbServer.ConfigDetail.Host = host
								}
								if startTime, ok := result["startTime"].(string); ok {
									dbServer.ConfigDetail.StartTime = startTime
								}
								if satisfiesPzi, ok := result["satisfiesPzi"].(bool); ok {
									dbServer.ConfigDetail.SatisfiesPzi = satisfiesPzi
								}
								if annotations, ok := result["annotations"].(map[string]interface{}); ok {
									annotationsStr := make(map[string]string)
									for k, v := range annotations {
										if str, ok := v.(string); ok {
											annotationsStr[k] = str
										}
									}
									dbServer.ConfigDetail.Annotations = annotationsStr
								}
								if env, ok := result["env"].(map[string]interface{}); ok {
									envStr := make(map[string]string)
									for k, v := range env {
										if str, ok := v.(string); ok {
											envStr[k] = str
										}
									}
									dbServer.ConfigDetail.Env = envStr
								}
								if runtimeHost, ok := result["runtimeHost"].(map[string]interface{}); ok {
									dbServer.ConfigDetail.RuntimeHost = runtimeHost
								}
							}
						}
					}
				}
				if err := singleton.DB.Save(dbServer).Error; err != nil {
					fmt.Println("[ERROR] Save DB:", err)
				} else {
					rs, _ := singleton.ServerShared.Get(dbServer.ID)
					dbServer.CopyFromRunningServer(rs)
					singleton.ServerShared.Update(dbServer, "")
					mu.Lock()
					updatedServers = append(updatedServers, *dbServer)
					mu.Unlock()
				}
			}(&dbServers[idx])
		}
		wg.Wait()
	}
	return updatedServers, nil
}

func getServerListFromBithub() (any, error) {
	url := "https://the-bithub.com/server.json"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	var result any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// API: GET /api/v1/oauth2/:provider/:action/:mode
// action: start, stop, generateToken, list
func getWorkstation(c *gin.Context) (any, error) {
	provider := strings.ToLower(c.Param("provider"))
    if provider != "google" {
        return nil, singleton.Localizer.ErrorT("only support google provider")
    }
	
	action := c.Param("action")
	mode := c.Param("mode")

	var servers []uint64
	var tokenexp int64
	var port int64

	if action == "token" {
		type TokenUpdateRequest struct {
			Servers  []uint64 `json:"servers"`
			TokenExp int64    `json:"tokenexp"`
			Port     int64    `json:"port"`
		}

		var req TokenUpdateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			return nil, err
		}
		servers = req.Servers
		tokenexp = req.TokenExp
		port = req.Port
	} else {
		if err := c.ShouldBindJSON(&servers); err != nil {
			return nil, err
		}
		tokenexp = 24 // default 24 hours
		port = -1     // default all ports
	}
	

	if !singleton.ServerShared.CheckPermission(c, slices.Values(servers)) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}

	// Validate action
	validActions := map[string]bool{"start": true, "stop": true, "token": true, "list": true}
	if !validActions[action] {
		return nil, singleton.Localizer.ErrorT("invalid action. Supported actions: start, stop, generateToken, list")
	}
	
	u := c.MustGet(model.CtxKeyAuthorizedUser).(*model.User)
	var bind model.Oauth2Bind
	err := singleton.DB.Where("provider = ? AND user_id = ?", provider, u.ID).First(&bind).Error
	if err != nil {
		return nil, singleton.Localizer.ErrorT("oauth2 not binded")
	}
	
	// Lấy clientID, clientSecret từ config
	conf, ok := singleton.Conf.Oauth2[provider]
	if !ok {
		return nil, singleton.Localizer.ErrorT("provider config not found")
	}

	// --- Sử dụng thư viện oauth2 để tự động refresh token ---
	importCtx := context.Background()
	token := &oauth2.Token{
		AccessToken:  bind.AccessToken,
		RefreshToken: bind.RefreshToken,
		Expiry:       time.Unix(bind.TokenExpiry, 0),
	}
	oauthConf := &oauth2.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		Endpoint:     google.Endpoint,
	}
	tokenSource := oauthConf.TokenSource(importCtx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, singleton.Localizer.ErrorT("refresh token failed: "+err.Error())
	}
	// Nếu token mới khác token cũ, lưu lại vào DB
	if newToken.AccessToken != bind.AccessToken {
		bind.AccessToken = newToken.AccessToken
		bind.TokenExpiry = newToken.Expiry.Unix()
		singleton.DB.Save(&bind)
	}
	// --- End oauth2 ---
	type Result struct {
		ID     uint64      `json:"id"`
		Result interface{} `json:"result"`
		Error  string      `json:"error,omitempty"`
	}

	// Channel để giới hạn số goroutine đồng thời
	maxWorkers := 20
	sem := make(chan struct{}, maxWorkers)

	results := make([]Result, len(servers))
	var wg sync.WaitGroup

	for i, id := range servers {
		wg.Add(1)
		sem <- struct{}{} // chặn nếu đã đủ 20 goroutine
		go func(i int, id uint64) {
			defer wg.Done()
			defer func() { <-sem }() // giải phóng slot

					serverIdStr := fmt.Sprintf("%d", id)
		result, err := callWorkstationAPI(c, newToken.AccessToken, serverIdStr, action, mode, tokenexp, port)
		if err != nil {
			results[i] = Result{ID: id, Error: err.Error()}
			return
		}
		results[i] = Result{ID: id, Result: result}
		}(i, id)
	}
	wg.Wait()
	return results, nil
}

func callWorkstationAPI(c *gin.Context,accessToken, serverIdStr, action, mode string, ttl, port int64) (map[string]interface{}, error) {
	var url string
	var method string
	var body io.Reader
	
	// Lấy thông tin từ server ID
	serverId, err := strconv.ParseUint(serverIdStr, 10, 64)
	if err != nil {
		return nil, singleton.Localizer.ErrorT("invalid server id")
	}
	
	var s interface{}
	if mode == "serverlist" {
		var serverList model.ServerList
		if err := singleton.DB.First(&serverList, serverId).Error; err != nil {
			return nil, singleton.Localizer.ErrorT("server list id %d does not exist", serverId)
		}
		s = &serverList
	} else {
		var server model.Server
		if err := singleton.DB.First(&server, serverId).Error; err != nil {
			return nil, singleton.Localizer.ErrorT("server id %d does not exist", serverId)
		}
		s = &server
	}

	// Kiểm tra quyền truy cập
	if server, ok := s.(*model.Server); ok {
		if !server.HasPermission(c) {
			return nil, singleton.Localizer.ErrorT("permission denied")
		}
	} else if serverList, ok := s.(*model.ServerList); ok {
		if !serverList.HasPermission(c) {
			return nil, singleton.Localizer.ErrorT("permission denied")
		}
	}
	
	// Lấy thông tin cấu hình
	var serverUri, currentAccessToken string
	var tokenExp int64
	
	if server, ok := s.(*model.Server); ok {
		serverUri = server.ConfigDetail.Name
		currentAccessToken = server.ConfigDetail.Token
		tokenExp = server.ConfigDetail.TokenExpiry
	} else if serverList, ok := s.(*model.ServerList); ok {
		serverUri = serverList.ConfigDetail.Name
		currentAccessToken = serverList.ConfigDetail.Token
		tokenExp = serverList.ConfigDetail.TokenExpiry
	}
	baseURL := "https://workstations.googleapis.com/v1beta/" + serverUri
	
	switch action {
	case "list":
		url = baseURL
		method = "GET"
		body = nil

		
	case "start":
		// Start workstation
		url = fmt.Sprintf("%s:start", baseURL)
		method = "POST"
		body = nil
		
	case "stop":
		// Stop workstation
		url = fmt.Sprintf("%s:stop", baseURL)
		method = "POST"
		body = nil
		
	case "token":
		// Generate access token for workstation
		if tokenExp-time.Now().Unix() > 3600 && port == -1 {
			expTime := time.Unix(tokenExp, 0).UTC()
			result := map[string]interface{}{
				"accessToken": currentAccessToken,
				"expireTime": expTime.Format(time.RFC3339Nano),          
			}
			return result, nil
		}
		url = fmt.Sprintf("%s:generateAccessToken", baseURL)
		method = "POST"
		requestBody := map[string]string{
			"ttl": fmt.Sprintf("%ds", ttl *3600),
		}

		if port != -1 {
			requestBody["port"] = fmt.Sprintf("%d", port)
		}
		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(string(bodyBytes))
		
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
	}
	
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Google Workstations API error (status %d): %s", resp.StatusCode, string(responseBody))
	}
	
	// Parse response body
	var apiResp map[string]interface{}
	if err := json.Unmarshal(responseBody, &apiResp); err != nil {
		return nil, err
	}
	
	// Extract only done status for simple response
	result := map[string]interface{}{
		"done": apiResp["done"],
	}
	
	if action == "token" && port == -1 {
		var tokenResp map[string]interface{}
		if err := json.Unmarshal(responseBody, &tokenResp); err != nil {
			return nil, err
		}

		// Cập nhật token cho server hoặc server list
		if server, ok := s.(*model.Server); ok {
			if accessToken, ok := tokenResp["accessToken"].(string); ok {
				server.ConfigDetail.Token = accessToken
			}
			if expireTime, ok := tokenResp["expireTime"].(string); ok {
				if parsedTime, err := time.Parse(time.RFC3339Nano, expireTime); err == nil {
					server.ConfigDetail.TokenExpiry = parsedTime.Unix()
				}
			}

			// Lưu server vào database
			if err := singleton.DB.Save(server).Error; err != nil {
				return nil, newGormError("%v", err)
			}
		
			// Cập nhật cache
			rs, _ := singleton.ServerShared.Get(server.ID)
			server.CopyFromRunningServer(rs)
			singleton.ServerShared.Update(server, "")
		} else if serverList, ok := s.(*model.ServerList); ok {
			if accessToken, ok := tokenResp["accessToken"].(string); ok {
				serverList.ConfigDetail.Token = accessToken
			}
			if expireTime, ok := tokenResp["expireTime"].(string); ok {
				if parsedTime, err := time.Parse(time.RFC3339Nano, expireTime); err == nil {
					serverList.ConfigDetail.TokenExpiry = parsedTime.Unix()
				}
			}

			// Lưu server list vào database
			if err := singleton.DB.Save(serverList).Error; err != nil {
				return nil, newGormError("%v", err)
			}
		}
	}
	
	return result, nil
}


func getWorkstationDetail(c *gin.Context) (any, error) {
	provider := strings.ToLower(c.Param("provider"))
    if provider != "google" {
        return nil, singleton.Localizer.ErrorT("only support google provider")
    }
	
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}

	var s model.Server
	if err := singleton.DB.First(&s, id).Error; err != nil {
		return nil, singleton.Localizer.ErrorT("server id %d does not exist", id)
	}

	if !s.HasPermission(c) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}

	//Lay zone, projectId, clusterId, workstationId tu server
	zone := s.Zone
	projectId := s.ProjectID
	clusterId := s.ClusterID
	workstationId := s.Name
	

	u := c.MustGet(model.CtxKeyAuthorizedUser).(*model.User)
	var bind model.Oauth2Bind
	err = singleton.DB.Where("provider = ? AND user_id = ?", provider, u.ID).First(&bind).Error
	if err != nil {
		return nil, singleton.Localizer.ErrorT("oauth2 not binded")
	}
	
	// Lấy clientID, clientSecret từ config
	conf, ok := singleton.Conf.Oauth2[provider]
	if !ok {
		return nil, singleton.Localizer.ErrorT("provider config not found")
	}

	// --- Sử dụng thư viện oauth2 để tự động refresh token ---
	importCtx := context.Background()
	token := &oauth2.Token{
		AccessToken:  bind.AccessToken,
		RefreshToken: bind.RefreshToken,
		Expiry:       time.Unix(bind.TokenExpiry, 0),
	}
	oauthConf := &oauth2.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		Endpoint:     google.Endpoint,
	}
	tokenSource := oauthConf.TokenSource(importCtx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, singleton.Localizer.ErrorT("refresh token failed: "+err.Error())
	}
	// Nếu token mới khác token cũ, lưu lại vào DB
	if newToken.AccessToken != bind.AccessToken {
		bind.AccessToken = newToken.AccessToken
		bind.TokenExpiry = newToken.Expiry.Unix()
		singleton.DB.Save(&bind)
	}
	// --- End oauth2 ---

	// Gọi Google Cloud Workstations API
	body, err := callWorkstationDetailAPI(c, newToken.AccessToken, zone, projectId, clusterId, workstationId)
	if err != nil {
		return nil, singleton.Localizer.ErrorT("call workstation api failed: "+err.Error())
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	// Lưu các field từ result vào ConfigDetail
	if name, ok := result["name"].(string); ok {
		s.ConfigDetail.Name = name
	}
	if displayName, ok := result["displayName"].(string); ok {
		s.ConfigDetail.DisplayName = displayName
	}
	if uid, ok := result["uid"].(string); ok {
		s.ConfigDetail.Uid = uid
	}
	if createTime, ok := result["createTime"].(string); ok {
		s.ConfigDetail.CreateTime = createTime
	}
	if updateTime, ok := result["updateTime"].(string); ok {
		s.ConfigDetail.UpdateTime = updateTime
	}
	if etag, ok := result["etag"].(string); ok {
		s.ConfigDetail.Etag = etag
	}
	if state, ok := result["state"].(string); ok {
		s.ConfigDetail.State = state
	}
	if host, ok := result["host"].(string); ok {
		s.ConfigDetail.Host = host
	}
	if startTime, ok := result["startTime"].(string); ok {
		s.ConfigDetail.StartTime = startTime
	}
	if satisfiesPzi, ok := result["satisfiesPzi"].(bool); ok {
		s.ConfigDetail.SatisfiesPzi = satisfiesPzi
	}
	
	// Cập nhật map fields nếu có
	if annotations, ok := result["annotations"].(map[string]interface{}); ok {
		// Convert map[string]interface{} to map[string]string
		annotationsStr := make(map[string]string)
		for k, v := range annotations {
			if str, ok := v.(string); ok {
				annotationsStr[k] = str
			}
		}
		s.ConfigDetail.Annotations = annotationsStr
	}
	if env, ok := result["env"].(map[string]interface{}); ok {
		// Convert map[string]interface{} to map[string]string
		envStr := make(map[string]string)
		for k, v := range env {
			if str, ok := v.(string); ok {
				envStr[k] = str
			}
		}
		s.ConfigDetail.Env = envStr
	}
	if runtimeHost, ok := result["runtimeHost"].(map[string]interface{}); ok {
		s.ConfigDetail.RuntimeHost = runtimeHost
	}
	
	// Lưu vào database
	if err := singleton.DB.Save(&s).Error; err != nil {
		return nil, newGormError("%v", err)
	}

	// Cập nhật cache
	rs, _ := singleton.ServerShared.Get(s.ID)
	s.CopyFromRunningServer(rs)
	singleton.ServerShared.Update(&s, "")

	fmt.Println("result", result)
	return result, nil
}

func callWorkstationDetailAPI(c *gin.Context,accessToken,zone,projectId,clusterId,workstationId string) ([]byte, error) {
	var method string
	var body io.Reader
	
	apiURL := fmt.Sprintf("https://workstations.googleapis.com/v1beta/projects/%s/locations/%s/workstationClusters/%s/workstationConfigs/monospace-config-android-studio/workstations/%s", projectId, zone, clusterId, workstationId)
	method = "GET"
	body = nil
	
	req, err := http.NewRequest(method, apiURL, body)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Google Workstations API error (status %d): %s", resp.StatusCode, string(responseBody))
	}
	
	return responseBody, nil
}