package singleton

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/nezhahq/nezha/model"
)

const (
	WorkstationAPIBaseURL = "https://workstations.googleapis.com/v1beta"
	MaxRetries           = 5
	MaxConcurrent        = 30
)

type WorkstationService struct {
	accessToken string
	client      *http.Client
}

type WorkstationResponse struct {
	Workstations  []Workstation `json:"workstations,omitempty"`
	NextPageToken string        `json:"nextPageToken,omitempty"`
}

type Workstation struct {
	Name         string            `json:"name,omitempty"`
	DisplayName  string            `json:"displayName,omitempty"`
	Uid          string            `json:"uid,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	CreateTime   string            `json:"createTime,omitempty"`
	UpdateTime   string            `json:"updateTime,omitempty"`
	Etag         string            `json:"etag,omitempty"`
	State        string            `json:"state,omitempty"`
	Host         string            `json:"host,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
	StartTime    string            `json:"startTime,omitempty"`
	SatisfiesPzi bool              `json:"satisfiesPzi,omitempty"`
	RuntimeHost  map[string]interface{} `json:"runtimeHost,omitempty"`
}

type ClusterResult struct {
	Project  string
	Cluster  string
	Status   int
	Data     *WorkstationResponse
	Error    string
}

type LocationProjects map[string][]string

var (
	WorkstationShared *WorkstationService
	locationProjects  = LocationProjects{
		"asia-east1": {"712605920671", "5120269316"},
		"us-east4": {"312045414151"},
	}
	clusterIDs = []string{
		"workstation-cluster",
		"workstation-cluster-2",
		"workstation-cluster-3",
		"workstation-cluster-4",
		"workstation-cluster-5",
		"workstation-cluster-6",
		"workstation-cluster-7",
		"workstation-cluster-8",
		"workstation-cluster-9",
		"workstation-cluster-10",
	}
	retryableStatusCodes = map[int]bool{
		503: true,
		504: true,
	}
)

func InitWorkstationService(accessToken string) {
	WorkstationShared = &WorkstationService{
		accessToken: accessToken,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (ws *WorkstationService) fetchCluster(projectID, clusterID, location string) (*ClusterResult, error) {	
	allWorkstations := []Workstation{}
	pageToken := ""

	for {
		url := fmt.Sprintf("%s/projects/%s/locations/%s/workstationClusters/%s/workstationConfigs/monospace-config-android-studio/workstations:listUsable?pageSize=3",
			WorkstationAPIBaseURL, projectID, location, clusterID)
		
		if pageToken != "" {
			url += "&pageToken=" + pageToken
		}

		success := false
		var response *WorkstationResponse
		var statusCode int

		for attempt := 1; attempt <= MaxRetries; attempt++ {
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return nil, err
			}

			req.Header.Set("Authorization", "Bearer "+ws.accessToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := ws.client.Do(req)
			if err != nil {
				fmt.Printf("❌ Retry\n")
				if attempt < MaxRetries {
					time.Sleep(time.Duration(1<<attempt) * time.Second)
					continue
				}
				return &ClusterResult{
					Project: projectID,
					Cluster: clusterID,
					Status:  -1,
					Error:   err.Error(),
				}, nil
			}

			statusCode = resp.StatusCode
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()

			if err != nil {
				return nil, err
			}

			if statusCode == 200 {
				if err := json.Unmarshal(body, &response); err != nil {
					return nil, err
				}
				allWorkstations = append(allWorkstations, response.Workstations...)
				pageToken = response.NextPageToken
				success = true
				break
			} else if retryableStatusCodes[statusCode] {
				fmt.Printf("⏳ Retryable (%d) -> %s/%s, wait %ds...\n", statusCode, projectID, clusterID, 1<<attempt)
				time.Sleep(time.Duration(1<<attempt) * time.Second)
			} else {
				return &ClusterResult{
					Project: projectID,
					Cluster: clusterID,
					Status:  statusCode,
					Error:   string(body),
				}, nil
			}
		}

		if !success {
			return &ClusterResult{
				Project: projectID,
				Cluster: clusterID,
				Status:  -1,
				Error:   fmt.Sprintf("Failed after %d retries", MaxRetries),
			}, nil
		}

		if pageToken == "" {
			break
		}
	}

	return &ClusterResult{
		Project: projectID,
		Cluster: clusterID,
		Status:  200,
		Data: &WorkstationResponse{
			Workstations: allWorkstations,
		},
	}, nil
}

func (ws *WorkstationService) FetchAllWorkstations() ([]Workstation, error) {
	start := time.Now()
	
	// Tạo semaphore để giới hạn số request đồng thời
	semaphore := make(chan struct{}, MaxConcurrent)
	var wg sync.WaitGroup
	
	results := make(chan *ClusterResult, 100)
	errors := make(chan error, 100)

	// Tạo tasks
	for location, projectIDs := range locationProjects {
		for _, projectID := range projectIDs {
			for _, clusterID := range clusterIDs {
				wg.Add(1)
				go func(loc, proj, clust string) {
					defer wg.Done()
					
					// Acquire semaphore
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					result, err := ws.fetchCluster(proj, clust, loc)
					if err != nil {
						errors <- err
						return
					}
					results <- result
				}(location, projectID, clusterID)
			}
		}
	}

	// Đóng channels khi tất cả goroutines hoàn thành
	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	// Thu thập kết quả
	var allWorkstations []Workstation
	var allErrors []error

	// Xử lý errors
	for err := range errors {
		allErrors = append(allErrors, err)
	}

	// Xử lý results
	for result := range results {
		if result.Status == 200 && result.Data != nil {
			allWorkstations = append(allWorkstations, result.Data.Workstations...)
		} else {
			if result.Error != "" {
				fmt.Printf("    Error: %s\n")
			}
		}
	}

	elapsed := time.Since(start).Seconds()
	fmt.Printf("\n🎯 Tổng cộng: %d workstations\n", len(allWorkstations))
	fmt.Printf("⏱️ Thời gian xử lý: %.2f giây\n", elapsed)

	if len(allErrors) > 0 {
		return allWorkstations, fmt.Errorf("encountered %d errors", len(allErrors))
	}

	return allWorkstations, nil
}

// SyncWorkstationsToDatabase đồng bộ workstations vào database
func (ws *WorkstationService) SyncWorkstationsToDatabase(userID uint64) error {
	workstations, err := ws.FetchAllWorkstations()
	if err != nil {
		return err
	}

	// Lấy danh sách server lists hiện tại của user
	var existingServerLists []model.ServerList
	if err := DB.Where("user_id = ?", userID).Find(&existingServerLists).Error; err != nil {
		return err
	}

	// Tạo map để tìm kiếm nhanh workstation theo UID
	existingMap := make(map[string]model.ServerList)
	for _, serverList := range existingServerLists {
		if serverList.ConfigDetail.Uid != "" {
			existingMap[serverList.ConfigDetail.Uid] = serverList
		}
	}

	// Tạo map để theo dõi workstations đã xử lý
	processedUIDs := make(map[string]bool)
	var createdCount, updatedCount int

	// Xử lý từng workstation
	for _, workstation := range workstations {
		configDetail := model.ConfigDetail{
			Name:         workstation.Name,
			DisplayName:  workstation.DisplayName,
			Uid:          workstation.Uid,
			Annotations:  workstation.Annotations,
			CreateTime:   workstation.CreateTime,
			UpdateTime:   workstation.UpdateTime,
			Etag:         workstation.Etag,
			State:        workstation.State,
			Host:         workstation.Host,
			Env:          workstation.Env,
			StartTime:    workstation.StartTime,
			SatisfiesPzi: workstation.SatisfiesPzi,
			RuntimeHost:  workstation.RuntimeHost,
		}

		if existingServerList, exists := existingMap[workstation.Uid]; exists {
			// Cập nhật workstation đã tồn tại
			existingServerList.Name = workstation.Annotations["IDX_WORKSPACE"]
			existingServerList.ConfigDetail = configDetail
			existingServerList.UpdatedAt = time.Now()

			if err := DB.Save(&existingServerList).Error; err != nil {
				return err
			}
			updatedCount++
		} else {
			// Tạo workstation mới
			serverList := model.ServerList{
				Common: model.Common{
					UserID: userID,
				},
				Name:         workstation.Annotations["IDX_WORKSPACE"],
				ConfigDetail: configDetail,
			}

			if err := DB.Create(&serverList).Error; err != nil {
				return err
			}
			createdCount++
		}

		processedUIDs[workstation.Uid] = true
	}

	// Xóa các workstations không còn tồn tại trong GCP
	var workstationsToDelete []uint64
	for _, existingServerList := range existingServerLists {
		if !processedUIDs[existingServerList.ConfigDetail.Uid] {
			workstationsToDelete = append(workstationsToDelete, existingServerList.ID)
		}
	}

	if len(workstationsToDelete) > 0 {
		if err := DB.Delete(&model.ServerList{}, workstationsToDelete).Error; err != nil {
			return err
		}
	}

	fmt.Printf("✅ Đã đồng bộ %d workstations vào database cho user %d\n", len(workstations), userID)
	fmt.Printf("   - Tạo mới: %d\n", createdCount)
	fmt.Printf("   - Cập nhật: %d\n", updatedCount)
	fmt.Printf("   - Xóa: %d\n", len(workstationsToDelete))

	return nil
} 