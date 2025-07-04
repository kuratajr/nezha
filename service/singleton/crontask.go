package singleton

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jinzhu/copier"

	"github.com/robfig/cron/v3"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/utils"
	pb "github.com/nezhahq/nezha/proto"
	"io"
	"net/http"
	"context"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
	"encoding/json"
	"sync"
)

type CronClass struct {
	class[uint64, *model.Cron]
	*cron.Cron
}

func NewCronClass() *CronClass {
	cronx := cron.New(cron.WithSeconds(), cron.WithLocation(Loc))
	list := make(map[uint64]*model.Cron)

	var sortedList []*model.Cron
	DB.Find(&sortedList)

	var err error
	var notificationGroupList []uint64
	notificationMsgMap := make(map[uint64]*strings.Builder)

	for _, cron := range sortedList {
		// 触发任务类型无需注册
		if cron.TaskType == model.CronTypeTriggerTask {
			list[cron.ID] = cron
			continue
		}
		// 注册计划任务
		cron.CronJobID, err = cronx.AddFunc(cron.Scheduler, CronTrigger(cron))
		if err == nil {
			list[cron.ID] = cron
		} else {
			// 当前通知组首次出现 将其加入通知组列表并初始化通知组消息缓存
			if _, ok := notificationMsgMap[cron.NotificationGroupID]; !ok {
				notificationGroupList = append(notificationGroupList, cron.NotificationGroupID)
				notificationMsgMap[cron.NotificationGroupID] = new(strings.Builder)
				notificationMsgMap[cron.NotificationGroupID].WriteString(Localizer.T("Tasks failed to register: ["))
			}
			notificationMsgMap[cron.NotificationGroupID].WriteString(fmt.Sprintf("%d,", cron.ID))
		}
	}

	// 向注册错误的计划任务所在通知组发送通知
	for _, gid := range notificationGroupList {
		notificationMsgMap[gid].WriteString(Localizer.T("] These tasks will not execute properly. Fix them in the admin dashboard."))
		NotificationShared.SendNotification(gid, notificationMsgMap[gid].String(), "")
	}
	cronx.Start()

	return &CronClass{
		class: class[uint64, *model.Cron]{
			list:       list,
			sortedList: sortedList,
		},
		Cron: cronx,
	}
}

func (c *CronClass) Update(cr *model.Cron) {
	c.listMu.Lock()
	crOld := c.list[cr.ID]
	if crOld != nil && crOld.CronJobID != 0 {
		c.Cron.Remove(crOld.CronJobID)
	}

	delete(c.list, cr.ID)
	c.list[cr.ID] = cr
	c.listMu.Unlock()

	c.sortList()
}

func (c *CronClass) Delete(idList []uint64) {
	c.listMu.Lock()
	for _, id := range idList {
		cr := c.list[id]
		if cr != nil && cr.CronJobID != 0 {
			c.Cron.Remove(cr.CronJobID)
		}
		delete(c.list, id)
	}
	c.listMu.Unlock()

	c.sortList()
}

func (c *CronClass) sortList() {
	c.listMu.RLock()
	defer c.listMu.RUnlock()

	sortedList := utils.MapValuesToSlice(c.list)
	slices.SortFunc(sortedList, func(a, b *model.Cron) int {
		return cmp.Compare(a.ID, b.ID)
	})

	c.sortedListMu.Lock()
	defer c.sortedListMu.Unlock()
	c.sortedList = sortedList
}

func (c *CronClass) SendTriggerTasks(taskIDs []uint64, triggerServer uint64) {
	c.listMu.RLock()
	var cronLists []*model.Cron
	for _, taskID := range taskIDs {
		if c, ok := c.list[taskID]; ok {
			cronLists = append(cronLists, c)
		}
	}
	c.listMu.RUnlock()

	// 依次调用CronTrigger发送任务
	for _, c := range cronLists {
		go CronTrigger(c, triggerServer)()
	}
}

func ManualTrigger(cr *model.Cron) {
	CronTrigger(cr)()
}

const (
	// Batch size for concurrent processing
	BATCH_SIZE = 20
)

func CronTrigger(cr *model.Cron, triggerServer ...uint64) func() {
	crIgnoreMap := make(map[uint64]bool)
	for _, server := range cr.Servers {
		crIgnoreMap[server] = true
	}
	
	return func() {
		if cr.Cover == model.CronCoverAlertTrigger {
			if len(triggerServer) == 0 {
				return
			}
			if s, ok := ServerShared.Get(triggerServer[0]); ok {
				
				if s.TaskStream != nil {
					s.TaskStream.Send(&pb.Task{
						Id:   cr.ID,
						Data: cr.Command,
						Type: model.TaskTypeCommand,
					})
				} else {
					// 保存当前服务器状态信息
					curServer := model.Server{}
					copier.Copy(&curServer, s)
					go NotificationShared.SendNotification(cr.NotificationGroupID, Localizer.Tf("[Task failed] %s: server %s is offline and cannot execute the task", cr.Name, s.Name), "", &curServer)
				}
			}
			return
		}

		var bind model.Oauth2Bind

		if cr.Live {
			//Lấy accessToken từ DB	
			err := DB.Where("provider = ? AND user_id = ?", "google", 1).First(&bind).Error
			if err != nil {
				return
			}
			
			// Lấy clientID, clientSecret từ config
			conf, ok := Conf.Oauth2["google"]
			if !ok {
				return
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
				return
			}
			// Nếu token mới khác token cũ, lưu lại vào DB
			if newToken.AccessToken != bind.AccessToken {
				bind.AccessToken = newToken.AccessToken
				bind.TokenExpiry = newToken.Expiry.Unix()
				DB.Save(&bind)
			}
		}

		// Process servers in batches
		processServersInBatches(cr, crIgnoreMap, bind)
	}
}

// processServersInBatches processes servers in batches with concurrent execution
func processServersInBatches(cr *model.Cron, crIgnoreMap map[uint64]bool, bind model.Oauth2Bind) {
	// Collect all servers into a slice
	var servers []*model.Server
	ServerShared.Range(func(k uint64, v *model.Server) bool {
		servers = append(servers, v)
		return true
	})
	totalServers := len(servers)
	// Calculate number of batches
	numBatches := (totalServers + BATCH_SIZE - 1) / BATCH_SIZE
	// Process each batch sequentially
	for i := 0; i < numBatches; i++ {
		start := i * BATCH_SIZE
		end := start + BATCH_SIZE
		if end > totalServers {
			end = totalServers
		}
		batch := servers[start:end]
		fmt.Println("batch:", batch)
		var wg sync.WaitGroup
		for _, s := range batch {
			wg.Add(1)
			go func(server *model.Server) {
				defer wg.Done()
				processServerBatch(cr, server, crIgnoreMap, bind)
			}(s)
		}
		wg.Wait() // Wait for all servers in this batch to finish
	}
}

// processServerBatch processes a single server (not a batch anymore)
func processServerBatch(cr *model.Cron, s *model.Server, crIgnoreMap map[uint64]bool, bind model.Oauth2Bind) {
	fmt.Println("[", time.Now().Format(time.RFC3339), "] Live:", cr.Live)
	if cr.Live {
		var currentAccessToken string
		tokenExp := s.ConfigDetail.TokenExpiry
		baseURL := "https://workstations.googleapis.com/v1beta/" + s.ConfigDetail.Name
		if tokenExp-time.Now().Unix() > 3600  {
			currentAccessToken = s.ConfigDetail.Token
		} else {
			url := fmt.Sprintf("%s:generateAccessToken", baseURL)
			method := "POST"
			requestBody := map[string]string{
				"ttl": fmt.Sprintf("%ds", 24*3600),
			}
			bodyBytes, err := json.Marshal(requestBody)
			if err != nil {
				return
			}
			body := strings.NewReader(string(bodyBytes))
			req1, err := http.NewRequest(method, url, body)
			if err != nil {
				return
			}
			req1.Header.Set("Authorization", "Bearer "+bind.AccessToken)
			req1.Header.Set("Content-Type", "application/json")
			client1 := &http.Client{}
			resp1, err := client1.Do(req1)
			if err != nil {
				return
			}
			defer resp1.Body.Close()
			responseBody, err := io.ReadAll(resp1.Body)
			if err != nil {
				return
			}
			var respData map[string]interface{}
			err = json.Unmarshal(responseBody, &respData)
			if err != nil {
				return
			}
			if at, ok := respData["accessToken"].(string); ok {
				currentAccessToken = at
			} else {
				return
			}
		}
		callWorkStationLive(s.ConfigDetail.Name, s.ConfigDetail.Host, currentAccessToken, bind.AccessToken)
	}
	if cr.Cover == model.CronCoverAll && crIgnoreMap[s.ID] {
		return
	}
	if cr.Cover == model.CronCoverIgnoreAll && !crIgnoreMap[s.ID] {
		return
	}
	if s.TaskStream != nil {
		s.TaskStream.Send(&pb.Task{
			Id:   cr.ID,
			Data: cr.Command,
			Type: model.TaskTypeCommand,
		})
	} else {
		// 保存当前服务器状态信息
		curServer := model.Server{}
		copier.Copy(&curServer, s)
		go NotificationShared.SendNotification(cr.NotificationGroupID, Localizer.Tf("[Task failed] %s: server %s is offline and cannot execute the task", cr.Name, s.Name), "", &curServer)
	}
}

func callWorkStationLive(name, hostname, token, accessToken string) {
	var url string
	var method string
	var body io.Reader

	workstationUrl := "https://" + hostname + "/vnc.html?autoconnect=true&resize=remote&_=" + time.Now().Format(time.RFC3339)
	workspaceUrl := "https://workstations.googleapis.com/v1beta/" + name

	url = workstationUrl
	method = "GET"
	body = nil

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return
	}

	req.Header.Set("Cookie", "WorkstationJwtPartitioned="+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// responseBody, err := io.ReadAll(resp.Body)
	
	if err != nil {
		return
	}

	if resp.StatusCode < 200 {
		return
	}

	if resp.StatusCode == 404 {

		url = fmt.Sprintf("%s:start", workspaceUrl)	
		method = "POST"
		body = nil	
		
		req1, err := http.NewRequest(method, url, body)
		if err != nil {
			return
		}
		
		req1.Header.Set("Authorization", "Bearer " + accessToken)
		req1.Header.Set("Content-Type", "application/json")
		
		client1 := &http.Client{}
		resp1, err := client1.Do(req1)

		fmt.Println("start workstation:", resp1.StatusCode)

		if err != nil {
			return
		}
		defer resp1.Body.Close()		
	}

	fmt.Println("Live workstation:", resp.StatusCode)	

	return
}