package model

import (
	"github.com/gin-gonic/gin"
)

type ServerList struct {
	Common

	Name                   string `json:"name"`
	ConfigDetail           ConfigDetail `json:"config_detail,omitempty"` // 配置详情，存储配置文件内容
}

// HasPermission kiểm tra quyền truy cập cho ServerList
func (s *ServerList) HasPermission(ctx *gin.Context) bool {
	return s.Common.HasPermission(ctx)
}
