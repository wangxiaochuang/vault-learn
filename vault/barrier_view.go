package vault

import (
	"sync"

	"github.com/hashicorp/vault/sdk/logical"
)

// p18
type BarrierView struct {
	storage         *logical.StorageView
	readOnlyErr     error
	readOnlyErrLock sync.RWMutex
	iCheck          interface{}
}
