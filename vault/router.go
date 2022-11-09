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
