package vault

import (
	"context"
	"sync"

	"github.com/armon/go-radix"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/salt"
)

// p30
type Router struct {
	l                  sync.RWMutex
	root               *radix.Tree
	mountUUIDCache     *radix.Tree
	mountAccessorCache *radix.Tree
	tokenStoreSaltFunc func(context.Context) (*salt.Salt, error)
	storagePrefix      *radix.Tree
	logger             hclog.Logger
}

// p44
func NewRouter() *Router {
	r := &Router{
		root:               radix.New(),
		storagePrefix:      radix.New(),
		mountUUIDCache:     radix.New(),
		mountAccessorCache: radix.New(),
		// this will get replaced in production with a real logger but it's useful to have a default in place for tests
		logger: hclog.NewNullLogger(),
	}
	return r
}
