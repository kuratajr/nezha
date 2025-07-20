package model

import (
	"gorm.io/gorm"
)

// ServerListAPI cung cấp các function API cho ServerList
type ServerListAPI struct{}

// GetAllServerLists trả về toàn bộ dữ liệu ServerList từ database
func (api *ServerListAPI) GetAllServerLists(db *gorm.DB) ([]ServerList, error) {
	var serverLists []ServerList
	err := db.Find(&serverLists).Error
	return serverLists, err
}

// GetServerListByID trả về ServerList theo ID
func (api *ServerListAPI) GetServerListByID(db *gorm.DB, id uint64) (*ServerList, error) {
	var serverList ServerList
	err := db.First(&serverList, id).Error
	if err != nil {
		return nil, err
	}
	return &serverList, nil
}

// CreateServerList tạo mới ServerList
func (api *ServerListAPI) CreateServerList(db *gorm.DB, serverList *ServerList) error {
	return db.Create(serverList).Error
}

// UpdateServerList cập nhật ServerList
func (api *ServerListAPI) UpdateServerList(db *gorm.DB, serverList *ServerList) error {
	return db.Save(serverList).Error
}

// DeleteServerList xóa ServerList theo ID
func (api *ServerListAPI) DeleteServerList(db *gorm.DB, id uint64) error {
	return db.Delete(&ServerList{}, id).Error
}

// GetServerListsByUserID trả về ServerList theo UserID
func (api *ServerListAPI) GetServerListsByUserID(db *gorm.DB, userID uint64) ([]ServerList, error) {
	var serverLists []ServerList
	err := db.Where("user_id = ?", userID).Find(&serverLists).Error
	return serverLists, err
}

// Global instance để sử dụng
var ServerListAPIInstance = &ServerListAPI{} 