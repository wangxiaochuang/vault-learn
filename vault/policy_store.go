package vault

import (
	"sync"

	log "github.com/hashicorp/go-hclog"
	lru "github.com/hashicorp/golang-lru"
)

type entPolicyStore struct{}

// p175
type PolicyStore struct {
	entPolicyStore

	core    *Core
	aclView *BarrierView
	rgpView *BarrierView
	egpView *BarrierView

	tokenPoliciesLRU *lru.TwoQueueCache
	egpLRU           *lru.TwoQueueCache

	modifyLock *sync.RWMutex

	policyTypeMap sync.Map

	logger log.Logger
}
