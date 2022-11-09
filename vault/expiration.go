package vault

import (
	"context"
	"sync"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/fairshare"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	uberAtomic "go.uber.org/atomic"
)

// p95
type ExpirationManager struct {
	core       *Core
	router     *Router
	idView     *BarrierView
	tokenView  *BarrierView
	tokenStore *TokenStore
	logger     log.Logger

	pending     sync.Map
	nonexpiring sync.Map
	leaseCount  int
	pendingLock sync.RWMutex

	lockPerLease sync.Map
	irrevocable  sync.Map

	irrevocableLeaseCount int

	uniquePolicies      map[string][]string
	emptyUniquePolicies *time.Ticker

	tidyLock *int32

	restoreMode        *int32
	restoreModeLock    sync.RWMutex
	restoreRequestLock sync.RWMutex
	restoreLocks       []*locksutil.LockEntry
	restoreLoaded      sync.Map
	quitCh             chan struct{}

	coreStateLock     *DeadlockRWMutex
	quitContext       context.Context
	leaseCheckCounter *uint32

	logLeaseExpirations bool
	expireFunc          ExpireLeaseStrategy

	testRegisterAuthFailure uberAtomic.Bool

	jobManager *fairshare.JobManager
}

// p155
type ExpireLeaseStrategy func(context.Context, *ExpirationManager, string, *namespace.Namespace)
