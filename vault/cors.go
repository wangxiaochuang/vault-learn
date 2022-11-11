package vault

import (
	"sync"
	"sync/atomic"

	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/strutil"
)

const (
	CORSDisabled uint32 = iota
	CORSEnabled
)

var StdAllowedHeaders = []string{
	"Content-Type",
	"X-Requested-With",
	"X-Vault-AWS-IAM-Server-ID",
	"X-Vault-MFA",
	"X-Vault-No-Request-Forwarding",
	"X-Vault-Wrap-Format",
	"X-Vault-Wrap-TTL",
	"X-Vault-Policy-Override",
	"Authorization",
	consts.AuthHeaderName,
}

// p34
type CORSConfig struct {
	sync.RWMutex   `json:"-"`
	core           *Core
	Enabled        *uint32  `json:"enabled"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	AllowedHeaders []string `json:"allowed_headers,omitempty"`
}

// p126
func (c *CORSConfig) IsEnabled() bool {
	return atomic.LoadUint32(c.Enabled) == CORSEnabled
}

// p145
func (c *CORSConfig) IsValidOrigin(origin string) bool {
	// If we aren't enabling CORS then all origins are valid
	if !c.IsEnabled() {
		return true
	}

	c.RLock()
	defer c.RUnlock()

	if len(c.AllowedOrigins) == 0 {
		return false
	}

	if len(c.AllowedOrigins) == 1 && (c.AllowedOrigins)[0] == "*" {
		return true
	}

	return strutil.StrListContains(c.AllowedOrigins, origin)
}
