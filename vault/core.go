package vault

import (
	"context"
	"crypto/ecdsa"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/command/server"
	"github.com/hashicorp/vault/helper/metricsutil"
	"github.com/hashicorp/vault/physical/raft"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
	sr "github.com/hashicorp/vault/serviceregistration"
	"github.com/hashicorp/vault/vault/cluster"
	"github.com/hashicorp/vault/vault/quotas"
	"github.com/patrickmn/go-cache"
	uberAtomic "go.uber.org/atomic"
	"google.golang.org/grpc"
)

// p194
type unlockInformation struct {
	Parts [][]byte
	Nonce string
}

// p207
type migrationInformation struct {
	seal      Seal
	unsealKey []byte
}

// p223
type Core struct {
	entCore

	builtinRegistry BuiltinRegistry

	devToken string

	ha physical.HABackend

	storageType string

	redirectAddr string

	clusterAddr *atomic.Value

	physical physical.Backend

	serviceRegistration sr.ServiceRegistration

	hcpLinkStatus HCPLinkStatus

	underlyingPhysical physical.Backend

	seal Seal

	raftJoinDoneCh chan struct{}

	postUnsealStarted *uint32

	raftInfo *atomic.Value

	migrationInfo     *migrationInformation
	sealMigrationDone *uint32

	barrier SecurityBarrier

	router *Router

	logicalBackends map[string]logical.Factory

	credentialBackends map[string]logical.Factory

	auditBackends map[string]audit.Factory

	stateLock DeadlockRWMutex
	sealed    *uint32

	standby              bool
	perfStandby          bool
	standbyDoneCh        chan struct{}
	standbyStopCh        *atomic.Value
	manualStepDownCh     chan struct{}
	keepHALockOnStepDown *uint32
	heldHALock           physical.Lock

	shutdownDoneCh chan struct{}

	unlockInfo *unlockInformation

	generateRootConfig   *GenerateRootConfig
	generateRootProgress [][]byte
	generateRootLock     sync.Mutex

	barrierRekeyConfig  *SealConfig
	recoveryRekeyConfig *SealConfig
	rekeyLock           sync.RWMutex

	mounts *MountTable

	mountsLock sync.RWMutex

	mountMigrationTracker *sync.Map

	auth *MountTable

	authLock sync.RWMutex

	audit *MountTable

	auditLock sync.RWMutex

	auditBroker *AuditBroker

	auditedHeaders *AuditedHeadersConfig

	systemBackend   *SystemBackend
	loginMFABackend *LoginMFABackend

	cubbyholeBackend *CubbyholeBackend

	systemBarrierView *BarrierView

	expiration *ExpirationManager

	rollback *RollbackManager

	policyStore *PolicyStore

	tokenStore *TokenStore

	identityStore *IdentityStore

	activityLog *ActivityLog

	metricsCh chan struct{}

	metricsMutex sync.Mutex

	inFlightReqData *InFlightRequests

	mfaResponseAuthQueue     *LoginMFAPriorityQueue
	mfaResponseAuthQueueLock sync.Mutex

	metricSink *metricsutil.ClusterMetricSink

	defaultLeaseTTL time.Duration
	maxLeaseTTL     time.Duration

	baseLogger log.Logger
	logger     log.Logger

	logLevel              string
	sentinelTraceDisabled bool

	cachingDisabled bool
	physicalCache   physical.ToggleablePurgemonster

	logRequestsLevel *uberAtomic.Int32

	reloadFuncs map[string][]reloadutil.ReloadFunc

	reloadFuncsLock sync.RWMutex

	wrappingJWTKey *ecdsa.PrivateKey

	clusterName                     string
	clusterID                       uberAtomic.String
	clusterCipherSuites             []uint16
	clusterParamsLock               sync.RWMutex
	localClusterPrivateKey          *atomic.Value
	localClusterCert                *atomic.Value
	localClusterParsedCert          *atomic.Value
	clusterListenerAddrs            []*net.TCPAddr
	clusterHandler                  http.Handler
	requestForwardingConnectionLock sync.RWMutex
	leaderParamsLock                sync.RWMutex
	clusterLeaderParams             *atomic.Value
	clusterPeerClusterAddrsCache    *cache.Cache
	rpcClientConnContext            context.Context
	rpcClientConnCancelFunc         context.CancelFunc
	rpcClientConn                   *grpc.ClientConn
	rpcForwardingClient             *forwardingClient
	leaderUUID                      string

	corsConfig *CORSConfig

	atomicPrimaryClusterAddrs *atomic.Value

	atomicPrimaryFailoverAddrs *atomic.Value

	replicationState           *uint32
	activeNodeReplicationState *uint32

	uiConfig *UIConfig

	rawEnabled bool

	pluginDirectory string

	pluginFileUid int

	pluginFilePermissions int

	pluginCatalog *PluginCatalog

	enableMlock bool

	activeContext           context.Context
	activeContextCancelFunc *atomic.Value

	sealUnwrapper physical.Backend

	unsealWithStoredKeysLock sync.Mutex

	postUnsealFuncs []func()

	postRecoveryUnsealFuncs []func() error

	replicationFailure *uint32

	disablePerfStandby bool

	licensingStopCh chan struct{}

	allLoggers     []log.Logger
	allLoggersLock sync.RWMutex

	neverBecomeActive *uint32

	loadCaseSensitiveIdentityStore bool

	clusterListener *atomic.Value

	customListenerHeader *atomic.Value

	metricsHelper *metricsutil.MetricsHelper

	raftFollowerStates    *raft.FollowerStates
	raftTLSRotationStopCh chan struct{}
	pendingRaftPeers      *sync.Map

	rawConfig *atomic.Value

	coreNumber int

	secureRandomReader io.Reader

	recoveryMode bool

	clusterNetworkLayer cluster.NetworkLayer

	PR1103disabled bool

	quotaManager             *quotas.Manager
	clusterHeartbeatInterval time.Duration
	activityLogConfig        ActivityLogCoreConfig
	activeTime               time.Time
	keyRotateGracePeriod     *int64

	autoRotateCancel               context.CancelFunc
	numExpirationWorkers           int
	IndexHeaderHMACKey             uberAtomic.Value
	disableAutopilot               bool
	enableResponseHeaderHostname   bool
	enableResponseHeaderRaftNodeID bool
	disableSSCTokens               bool
	versionHistory                 map[string]VaultVersion
	effectiveSDKVersion            string
	rollbackPeriod                 time.Duration
}

// p656
type CoreConfig struct {
	entCoreConfig

	DevToken string

	BuiltinRegistry BuiltinRegistry

	LogicalBackends map[string]logical.Factory

	CredentialBackends map[string]logical.Factory

	AuditBackends map[string]audit.Factory

	Physical physical.Backend

	StorageType string

	// May be nil, which disables HA operations
	HAPhysical physical.HABackend

	ServiceRegistration sr.ServiceRegistration

	// Seal is the configured seal, or if none is configured explicitly, a
	// shamir seal.  In migration scenarios this is the new seal.
	Seal Seal

	// Unwrap seal is the optional seal marked "disabled"; this is the old
	// seal in migration scenarios.
	UnwrapSeal Seal

	SecureRandomReader io.Reader

	LogLevel string

	Logger log.Logger

	// Disables the trace display for Sentinel checks
	DisableSentinelTrace bool

	// Disables the LRU cache on the physical backend
	DisableCache bool

	// Disables mlock syscall
	DisableMlock bool

	// Custom cache size for the LRU cache on the physical backend, or zero for default
	CacheSize int

	// Set as the leader address for HA
	RedirectAddr string

	// Set as the cluster address for HA
	ClusterAddr string

	DefaultLeaseTTL time.Duration

	MaxLeaseTTL time.Duration

	ClusterName string

	ClusterCipherSuites string

	EnableUI bool

	// Enable the raw endpoint
	EnableRaw bool

	PluginDirectory string

	PluginFileUid int

	PluginFilePermissions int

	DisableSealWrap bool

	RawConfig *server.Config

	ReloadFuncs     *map[string][]reloadutil.ReloadFunc
	ReloadFuncsLock *sync.RWMutex

	// Licensing
	License         string
	LicensePath     string
	LicensingConfig *LicensingConfig

	DisablePerformanceStandby bool
	DisableIndexing           bool
	DisableKeyEncodingChecks  bool

	AllLoggers []log.Logger

	// Telemetry objects
	MetricsHelper *metricsutil.MetricsHelper
	MetricSink    *metricsutil.ClusterMetricSink

	RecoveryMode bool

	ClusterNetworkLayer cluster.NetworkLayer

	ClusterHeartbeatInterval time.Duration

	// Activity log controls
	ActivityLogConfig ActivityLogCoreConfig

	// number of workers to use for lease revocation in the expiration manager
	NumExpirationWorkers int

	// DisableAutopilot is used to disable autopilot subsystem in raft storage
	DisableAutopilot bool

	// Whether to send headers in the HTTP response showing hostname or raft node ID
	EnableResponseHeaderHostname   bool
	EnableResponseHeaderRaftNodeID bool

	// DisableSSCTokens is used to disable the use of server side consistent tokens
	DisableSSCTokens bool

	EffectiveSDKVersion string

	RollbackPeriod time.Duration
}

// p2987
type BuiltinRegistry interface {
	Contains(name string, pluginType consts.PluginType) bool
	Get(name string, pluginType consts.PluginType) (func() (interface{}, error), bool)
	Keys(pluginType consts.PluginType) []string
	DeprecationStatus(name string, pluginType consts.PluginType) (consts.DeprecationStatus, bool)
}

// 3224
type InFlightRequests struct {
	InFlightReqMap   *sync.Map
	InFlightReqCount *uberAtomic.Uint64
}

// p3457
type HCPLinkStatus struct {
	lock             sync.RWMutex
	ConnectionStatus string `json:"hcp_link_status,omitempty"`
	ResourceIDOnHCP  string `json:"resource_ID_on_hcp,omitempty"`
}
