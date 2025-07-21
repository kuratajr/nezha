package controller

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

type ServerListController struct{}

// ServerListFiltered chỉ chứa id, name và CREATOR_EMAIL
type ServerListFiltered struct {
	ID            uint64 `json:"id"`
	Name          string `json:"name"`
	Host          string `json:"host"`
	CreatorEmail  string `json:"creator_email,omitempty"`
}

// Handler functions để kết nối với routing system

// List server list filtered - chỉ trả về name và CREATOR_EMAIL
// @Summary List server list filtered
// @Security BearerAuth
// @Schemes
// @Description List server list with only name and CREATOR_EMAIL
// @Tags auth required
// @Param id query uint false "Resource ID"
// @Produce json
// @Success 200 {object} model.CommonResponse[[]ServerListFiltered]
// @Router /server-list/filtered [get]
func listServerListFiltered(c *gin.Context) ([]*ServerListFiltered, error) {
	// Lấy user hiện tại từ context
	user, exists := c.Get(model.CtxKeyAuthorizedUser)
	if !exists {
		return nil, errors.New("unauthorized: user not found in context")
	}
	userID := user.(*model.User).ID

	var serverLists []*model.ServerList
	err := singleton.DB.Where("user_id = ?", userID).Find(&serverLists).Error
	if err != nil {
		return nil, err
	}

	var filtered []*ServerListFiltered
	for _, serverList := range serverLists {
		filteredItem := &ServerListFiltered{
			ID:   serverList.ID,
			Name: serverList.Name,
			Host: serverList.ConfigDetail.Host,
		}
		// Lấy CREATOR_EMAIL từ ConfigDetail.Env
		if serverList.ConfigDetail.Env != nil {
			if creatorEmail, exists := serverList.ConfigDetail.Env["CREATOR_EMAIL"]; exists {
				filteredItem.CreatorEmail = creatorEmail
			}
		}
		filtered = append(filtered, filteredItem)
	}
	return filtered, nil
}

// List server list
// @Summary List server list
// @Security BearerAuth
// @Schemes
// @Description List server list
// @Tags auth required
// @Param id query uint false "Resource ID"
// @Produce json
// @Success 200 {object} model.CommonResponse[[]model.ServerList]
// @Router /server-list [get]
func listServerList(c *gin.Context) ([]*model.ServerList, error) {
	var serverLists []*model.ServerList
	err := singleton.DB.Find(&serverLists).Error
	return serverLists, err
}

// Get server list by ID
// @Summary Get server list by ID
// @Security BearerAuth
// @Schemes
// @Description Get server list by ID
// @Tags auth required
// @Param id path uint true "Server List ID"
// @Produce json
// @Success 200 {object} model.CommonResponse[ServerListFiltered]
// @Router /server-list/{id} [get]
func getServerListByID(c *gin.Context) (*ServerListFiltered, error) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}

	var serverList model.ServerList
	err = singleton.DB.First(&serverList, id).Error
	if err != nil {
		return nil, err
	}

	// Tạo ServerListFiltered từ serverList
	filteredItem := &ServerListFiltered{
		ID:   serverList.ID,
		Name: serverList.Name,
		Host: serverList.ConfigDetail.Host,
	}
	
	// Lấy CREATOR_EMAIL từ ConfigDetail.Env
	if serverList.ConfigDetail.Env != nil {
		if creatorEmail, exists := serverList.ConfigDetail.Env["CREATOR_EMAIL"]; exists {
			filteredItem.CreatorEmail = creatorEmail
		}
	}
	
	return filteredItem, nil
}

// Create server list
// @Summary Create server list
// @Security BearerAuth
// @Schemes
// @Description Create server list
// @Tags auth required
// @Accept json
// @Param body body model.ServerList true "ServerList"
// @Produce json
// @Success 200 {object} model.CommonResponse[uint64]
// @Router /server-list [post]
func createServerList(c *gin.Context) (uint64, error) {
	var serverList model.ServerList
	if err := c.ShouldBindJSON(&serverList); err != nil {
		return 0, err
	}

	// Lấy user ID từ context
	if user, exists := c.Get(model.CtxKeyAuthorizedUser); exists {
		serverList.UserID = user.(*model.User).ID
	}

	err := singleton.DB.Create(&serverList).Error
	if err != nil {
		return 0, err
	}

	return serverList.ID, nil
}

// Update server list
// @Summary Update server list
// @Security BearerAuth
// @Schemes
// @Description Update server list
// @Tags auth required
// @Accept json
// @Param id path uint true "Server List ID"
// @Param body body model.ServerList true "ServerList"
// @Produce json
// @Success 200 {object} model.CommonResponse[any]
// @Router /server-list/{id} [patch]
func updateServerList(c *gin.Context) (any, error) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}

	var serverList model.ServerList
	if err := c.ShouldBindJSON(&serverList); err != nil {
		return nil, err
	}

	serverList.ID = id
	err = singleton.DB.Save(&serverList).Error
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// Delete server list
// @Summary Delete server list
// @Security BearerAuth
// @Schemes
// @Description Delete server list
// @Tags auth required
// @Param id path uint true "Server List ID"
// @Produce json
// @Success 200 {object} model.CommonResponse[any]
// @Router /server-list/{id} [delete]
func deleteServerList(c *gin.Context) (any, error) {
    var servers []uint64
    if err := c.ShouldBindJSON(&servers); err != nil {
        return nil, err
    }

    err := singleton.DB.Delete(&model.ServerList{}, servers).Error
    if err != nil {
        return nil, err
    }

    return nil, nil
}
// Get server lists by user
// @Summary Get server lists by user
// @Security BearerAuth
// @Schemes
// @Description Get server lists by user
// @Tags auth required
// @Produce json
// @Success 200 {object} model.CommonResponse[[]model.ServerList]
// @Router /server-list/user [get]
func getServerListsByUser(c *gin.Context) ([]*model.ServerList, error) {
	if user, exists := c.Get(model.CtxKeyAuthorizedUser); exists {
		userID := user.(*model.User).ID
		var serverLists []*model.ServerList
		err := singleton.DB.Where("user_id = ?", userID).Find(&serverLists).Error
		return serverLists, err
	}
	return nil, singleton.Localizer.ErrorT("unauthorized")
}

// Sync workstations from Google Cloud Platform
// @Summary Sync workstations from GCP
// @Security BearerAuth
// @Schemes
// @Description Sync workstations from Google Cloud Platform
// @Tags auth required
// @Accept json
// @Produce json
// @Success 200 {object} model.CommonResponse[any]
// @Router /server-list/sync-gcp [post]
func syncWorkstationsFromGCP(c *gin.Context) (any, error) {
	provider := strings.ToLower(c.Param("provider"))
	if provider != "google" {
		return nil, singleton.Localizer.ErrorT("only support google provider")
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

	// Sử dụng thư viện oauth2 để tự động refresh token
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
		return nil, singleton.Localizer.ErrorT("refresh token failed: " + err.Error())
	}
	// Nếu token mới khác token cũ, lưu lại vào DB
	if newToken.AccessToken != bind.AccessToken {
		bind.AccessToken = newToken.AccessToken
		bind.TokenExpiry = newToken.Expiry.Unix()
		singleton.DB.Save(&bind)
	}

	// Khởi tạo workstation service
	singleton.InitWorkstationService(newToken.AccessToken)

	// Chạy sync trong background
	go func() {
		startTime := time.Now()
		fmt.Printf("🚀 Bắt đầu sync workstations cho user %d\n", u.ID)
		
		err := singleton.WorkstationShared.SyncWorkstationsToDatabase(u.ID)
		if err != nil {
			fmt.Printf("❌ Lỗi sync workstations cho user %d: %v\n", u.ID, err)
		} else {
			duration := time.Since(startTime)
			fmt.Printf("✅ Hoàn thành sync workstations cho user %d trong %v\n", u.ID, duration)
		}
	}()

	return map[string]interface{}{
		"message":     "Sync workstations đã được khởi chạy trong background",
		"user_id":     u.ID,
		"username":    u.Username,
		"provider":    provider,
		"status":      "started",
		"started_at":  time.Now().Format(time.RFC3339),
		"estimated_duration": "30-60 giây",
		"note":        "Kiểm tra console/logs để xem tiến trình",
		"locations":   []string{"asia-east1"},
		"total_clusters": 10,
	}, nil
}

// Get workstation detail by ID
// @Summary Get workstation detail by ID
// @Security BearerAuth
// @Schemes
// @Description Get workstation detail by ID
// @Tags auth required
// @Param id path uint true "Workstation ID"
// @Produce json
// @Success 200 {object} model.CommonResponse[model.ServerList]
// @Router /server-list/workstation/{id} [get]
func getWorkstationDetailByID(c *gin.Context) (*model.ServerList, error) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}

	var serverList model.ServerList
	err = singleton.DB.First(&serverList, id).Error
	if err != nil {
		return nil, err
	}

	// Kiểm tra quyền truy cập
	if !serverList.HasPermission(c) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}

	return &serverList, nil
}

// Update workstation list from GCP
// @Summary Update workstation list from GCP
// @Security BearerAuth
// @Schemes
// @Description Update workstation list from GCP
// @Tags auth required
// @Accept json
// @Produce json
// @Success 200 {object} model.CommonResponse[any]
// @Router /server-list/update-gcp [post]
func updateWorkstationListFromGCP(c *gin.Context) (any, error) {
	provider := strings.ToLower(c.Param("provider"))
	if provider != "google" {
		return nil, singleton.Localizer.ErrorT("only support google provider")
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

	// Sử dụng thư viện oauth2 để tự động refresh token
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
		return nil, singleton.Localizer.ErrorT("refresh token failed: " + err.Error())
	}
	// Nếu token mới khác token cũ, lưu lại vào DB
	if newToken.AccessToken != bind.AccessToken {
		bind.AccessToken = newToken.AccessToken
		bind.TokenExpiry = newToken.Expiry.Unix()
		singleton.DB.Save(&bind)
	}

	// Khởi tạo workstation service
	singleton.InitWorkstationService(newToken.AccessToken)

	// Chạy update trong background
	go func() {
		// Fetch workstations từ GCP
		workstations, err := singleton.WorkstationShared.FetchAllWorkstations()
		if err != nil {
			fmt.Printf("❌ Lỗi fetch workstations cho user %d: %v\n", u.ID, err)
			return
		}

		// Cập nhật database
		err = singleton.WorkstationShared.SyncWorkstationsToDatabase(u.ID)
		if err != nil {
			fmt.Printf("❌ Lỗi sync workstations cho user %d: %v\n", u.ID, err)
			return
		}

		fmt.Printf("✅ Đã cập nhật %d workstations cho user %d\n", len(workstations), u.ID)
	}()

	return map[string]interface{}{
		"message": "Update workstation list",
		"user_id": u.ID,
		"status":  "started",
	}, nil
} 



