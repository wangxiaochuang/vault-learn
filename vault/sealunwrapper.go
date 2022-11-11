package vault

import (
	"context"
	"sync/atomic"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/physical"
)

func NewSealUnwrapper(underlying physical.Backend, logger log.Logger) physical.Backend {
	ret := &sealUnwrapper{
		underlying:   underlying,
		logger:       logger,
		locks:        locksutil.CreateLocks(),
		allowUnwraps: new(uint32),
	}

	if underTxn, ok := underlying.(physical.Transactional); ok {
		return &transactionalSealUnwrapper{
			sealUnwrapper: ret,
			Transactional: underTxn,
		}
	}

	return ret
}

var (
	_ physical.Backend       = (*sealUnwrapper)(nil)
	_ physical.Transactional = (*transactionalSealUnwrapper)(nil)
)

type sealUnwrapper struct {
	underlying   physical.Backend
	logger       log.Logger
	locks        []*locksutil.LockEntry
	allowUnwraps *uint32
}

type transactionalSealUnwrapper struct {
	*sealUnwrapper
	physical.Transactional
}

func (d *sealUnwrapper) Put(ctx context.Context, entry *physical.Entry) error {
	panic("not implement")
}

func (d *sealUnwrapper) Get(ctx context.Context, key string) (*physical.Entry, error) {
	panic("not implement")
}

func (d *sealUnwrapper) Delete(ctx context.Context, key string) error {
	panic("not implement")
}

func (d *sealUnwrapper) List(ctx context.Context, prefix string) ([]string, error) {
	return d.underlying.List(ctx, prefix)
}

func (d *transactionalSealUnwrapper) Transaction(ctx context.Context, txns []*physical.TxnEntry) error {
	panic("not implement")
}

func (d *sealUnwrapper) stopUnwraps() {
	atomic.StoreUint32(d.allowUnwraps, 0)
}

func (d *sealUnwrapper) runUnwraps() {
	atomic.StoreUint32(d.allowUnwraps, 1)
}
