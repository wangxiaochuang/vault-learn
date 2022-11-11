package vault

import (
	"context"
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

func NewBarrierView(barrier logical.Storage, prefix string) *BarrierView {
	return &BarrierView{
		storage: logical.NewStorageView(barrier, prefix),
	}
}

func (v *BarrierView) setICheck(iCheck interface{}) {
	v.iCheck = iCheck
}

func (v *BarrierView) setReadOnlyErr(readOnlyErr error) {
	v.readOnlyErrLock.Lock()
	defer v.readOnlyErrLock.Unlock()
	v.readOnlyErr = readOnlyErr
}

func (v *BarrierView) getReadOnlyErr() error {
	v.readOnlyErrLock.RLock()
	defer v.readOnlyErrLock.RUnlock()
	return v.readOnlyErr
}

func (v *BarrierView) Prefix() string {
	return v.storage.Prefix()
}

func (v *BarrierView) List(ctx context.Context, prefix string) ([]string, error) {
	return v.storage.List(ctx, prefix)
}

func (v *BarrierView) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	return v.storage.Get(ctx, key)
}

// Put differs from List/Get because it checks read-only errors
func (v *BarrierView) Put(ctx context.Context, entry *logical.StorageEntry) error {
	panic("not implement")
}

// logical.Storage impl.
func (v *BarrierView) Delete(ctx context.Context, key string) error {
	panic("not implement")
}

// SubView constructs a nested sub-view using the given prefix
func (v *BarrierView) SubView(prefix string) *BarrierView {
	return &BarrierView{
		storage:     v.storage.SubView(prefix),
		readOnlyErr: v.getReadOnlyErr(),
		iCheck:      v.iCheck,
	}
}
