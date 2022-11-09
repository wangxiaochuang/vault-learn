package vault

import (
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-memdb"
	"github.com/patrickmn/go-cache"
)

// p99
type MFABackend struct {
	Core        *Core
	mfaLock     *sync.RWMutex
	db          *memdb.MemDB
	mfaLogger   hclog.Logger
	namespacer  Namespacer
	methodTable string
	usedCodes   *cache.Cache
}

// 109
type LoginMFABackend struct {
	*MFABackend
}
