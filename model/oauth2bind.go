package model

type Oauth2Bind struct {
	Common

	UserID   uint64 `gorm:"uniqueIndex:u_p_o" json:"user_id,omitempty"`
	Provider string `gorm:"uniqueIndex:u_p_o" json:"provider,omitempty"`
	OpenID   string `gorm:"uniqueIndex:u_p_o" json:"open_id,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenExpiry  int64  `json:"token_expiry,omitempty"`
}

type Oauth2LoginType uint8

const (
	_ Oauth2LoginType = iota
	RTypeLogin
	RTypeBind
)

type Oauth2State struct {
	Action      Oauth2LoginType
	Provider    string
	State       string
	RedirectURL string
}
