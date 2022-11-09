package vault

import "sync"

// p34
type CORSConfig struct {
	sync.RWMutex   `json:"-"`
	core           *Core
	Enabled        *uint32  `json:"enabled"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	AllowedHeaders []string `json:"allowed_headers,omitempty"`
}
