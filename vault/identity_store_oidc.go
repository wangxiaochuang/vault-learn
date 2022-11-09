package vault

import "github.com/patrickmn/go-cache"

// p99
type oidcCache struct {
	c *cache.Cache
}
