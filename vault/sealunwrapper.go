package vault

import (
	"context"
	"fmt"
	"sync/atomic"

	log "github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/physical"
	"google.golang.org/protobuf/proto"
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
	if entry == nil {
		return nil
	}

	locksutil.LockForKey(d.locks, entry.Key).Lock()
	defer locksutil.LockForKey(d.locks, entry.Key).Unlock()

	return d.underlying.Put(ctx, entry)
}

func (d *sealUnwrapper) Get(ctx context.Context, key string) (*physical.Entry, error) {
	entry, err := d.underlying.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var performUnwrap bool
	se := &wrapping.BlobInfo{}
	eLen := len(entry.Value)
	// 值以s结尾
	if eLen > 0 && entry.Value[eLen-1] == 's' {
		if err := proto.Unmarshal(entry.Value[:eLen-1], se); err == nil {
			performUnwrap = true
		}
	}
	if !performUnwrap {
		return entry, nil
	}
	if se.Wrapped {
		return nil, fmt.Errorf("cannot decode sealwrapped storage entry %q", entry.Key)
	}
	if atomic.LoadUint32(d.allowUnwraps) != 1 {
		return &physical.Entry{
			Key:   entry.Key,
			Value: se.Ciphertext,
		}, nil
	}

	locksutil.LockForKey(d.locks, key).Lock()
	defer locksutil.LockForKey(d.locks, key).Unlock()

	// 二次检查
	entry, err = d.underlying.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	performUnwrap = false
	se = &wrapping.BlobInfo{}
	eLen = len(entry.Value)
	if eLen > 0 && entry.Value[eLen-1] == 's' {
		if err := proto.Unmarshal(entry.Value[:eLen-1], se); err == nil {
			performUnwrap = true
		}
	}
	if !performUnwrap {
		return entry, nil
	}
	if se.Wrapped {
		return nil, fmt.Errorf("cannot decode sealwrapped storage entry %q", entry.Key)
	}

	entry = &physical.Entry{
		Key:   entry.Key,
		Value: se.Ciphertext,
	}

	if atomic.LoadUint32(d.allowUnwraps) != 1 {
		return entry, nil
	}
	return entry, d.underlying.Put(ctx, entry)
}

func (d *sealUnwrapper) Delete(ctx context.Context, key string) error {
	locksutil.LockForKey(d.locks, key).Lock()
	defer locksutil.LockForKey(d.locks, key).Unlock()

	return d.underlying.Delete(ctx, key)
}

func (d *sealUnwrapper) List(ctx context.Context, prefix string) ([]string, error) {
	return d.underlying.List(ctx, prefix)
}

func (d *transactionalSealUnwrapper) Transaction(ctx context.Context, txns []*physical.TxnEntry) error {
	var keys []string
	for _, curr := range txns {
		keys = append(keys, curr.Entry.Key)
	}
	// Lock the keys
	for _, l := range locksutil.LocksForKeys(d.locks, keys) {
		l.Lock()
		defer l.Unlock()
	}

	if err := d.Transactional.Transaction(ctx, txns); err != nil {
		return err
	}

	return nil
}

func (d *sealUnwrapper) stopUnwraps() {
	atomic.StoreUint32(d.allowUnwraps, 0)
}

func (d *sealUnwrapper) runUnwraps() {
	atomic.StoreUint32(d.allowUnwraps, 1)
}
