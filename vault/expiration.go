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

const (
	// expirationSubPath is the sub-path used for the expiration manager
	// view. This is nested under the system view.
	expirationSubPath = "expire/"

	// leaseViewPrefix is the prefix used for the ID based lookup of leases.
	leaseViewPrefix = "id/"

	// tokenViewPrefix is the prefix used for the token based lookup of leases.
	tokenViewPrefix = "token/"

	// maxRevokeAttempts limits how many revoke attempts are made
	maxRevokeAttempts = 6

	// revokeRetryBase is a baseline retry time
	revokeRetryBase = 10 * time.Second

	// maxLeaseDuration is the default maximum lease duration
	maxLeaseTTL = 32 * 24 * time.Hour

	// defaultLeaseDuration is the default lease duration used when no lease is specified
	defaultLeaseTTL = maxLeaseTTL

	// maxLeaseThreshold is the maximum lease count before generating log warning
	maxLeaseThreshold = 256000

	// numExpirationWorkersDefault is the maximum amount of workers working on lease expiration
	numExpirationWorkersDefault = 200

	// number of workers to use for general purpose testing
	numExpirationWorkersTest = 10

	fairshareWorkersOverrideVar = "VAULT_LEASE_REVOCATION_WORKERS"

	// limit irrevocable error messages to 240 characters to be respectful of
	// storage/memory
	maxIrrevocableErrorLength = 240

	genericIrrevocableErrorMessage = "unknown"

	outOfRetriesMessage = "out of retries"

	// maximum number of irrevocable leases we return to the irrevocable lease
	// list API **without** the `force` flag set
	MaxIrrevocableLeasesToReturn = 10000

	MaxIrrevocableLeasesWarning = "Command halted because many irrevocable leases were found. To emit the entire list, re-run the command with force set true."
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
