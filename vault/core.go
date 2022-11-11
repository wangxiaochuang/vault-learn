package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	vaultseal "github.com/hashicorp/vault/vault/seal"

	"github.com/hashicorp/errwrap"
	log "github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	aeadwrapper "github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/command/server"
	"github.com/hashicorp/vault/helper/metricsutil"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/physical/raft"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/tlsutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/sdk/version"
	sr "github.com/hashicorp/vault/serviceregistration"
	"github.com/hashicorp/vault/vault/cluster"
	"github.com/hashicorp/vault/vault/quotas"
	"github.com/patrickmn/go-cache"
	uberAtomic "go.uber.org/atomic"
	"google.golang.org/grpc"
)

const (
	CoreLockPath = "core/lock"

	poisonPillPath   = "core/poison-pill"
	poisonPillDRPath = "core/poison-pill-dr"

	coreLeaderPrefix = "core/leader/"

	coreKeyringCanaryPath = "core/canary-keyring"

	indexHeaderHMACKeyPath = "core/index-header-hmac-key"

	defaultMFAAuthResponseTTL = 300 * time.Second

	defaultMaxTOTPValidateAttempts = 5

	ForwardSSCTokenToActive = "new_token"

	WrapperTypeHsmAutoDeprecated = wrapping.WrapperType("hsm-auto")

	undoLogsAreSafeStoragePath = "core/raft/undo_logs_are_safe"
)

var (
	ErrAlreadyInit = errors.New("Vault is already initialized")

	ErrNotInit = errors.New("Vault is not initialized")

	ErrInternalError = errors.New("internal error")

	ErrHANotEnabled = errors.New("Vault is not configured for highly-available mode")

	manualStepDownSleepPeriod = 10 * time.Second

	storedLicenseCheck = func(c *Core, conf *CoreConfig) error { return nil }
	LicenseAutoloaded  = func(*Core) bool { return false }
	LicenseInitCheck   = func(*Core) error { return nil }
	LicenseReload      = func(*Core) error { return nil }
)

// p152
type NonFatalError struct {
	Err error
}

func (e *NonFatalError) WrappedErrors() []error {
	return []error{e.Err}
}

func (e *NonFatalError) Error() string {
	return e.Err.Error()
}

// p170
func IsFatalError(err error) bool {
	return !errwrap.ContainsType(err, new(NonFatalError))
}

// p194
type unlockInformation struct {
	Parts [][]byte
	Nonce string
}

// p199
type raftInformation struct {
	challenge           *wrapping.BlobInfo
	leaderClient        *api.Client
	leaderBarrierConfig *SealConfig
	nonVoter            bool
	joinInProgress      bool
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

// p780
func (c *CoreConfig) GetServiceRegistration() sr.ServiceRegistration {
	if c.ServiceRegistration != nil {
		return c.ServiceRegistration
	}

	if c.HAPhysical != nil && c.HAPhysical.HAEnabled() {
		if disc, ok := c.HAPhysical.(sr.ServiceRegistration); ok {
			return disc
		}
	}

	return nil
}

// p799
func CreateCore(conf *CoreConfig) (*Core, error) {
	if conf.HAPhysical != nil && conf.HAPhysical.HAEnabled() {
		if conf.RedirectAddr == "" {
			return nil, fmt.Errorf("missing API address, please set in configuration or via environment")
		}
	}
	if conf.DefaultLeaseTTL == 0 {
		conf.DefaultLeaseTTL = defaultLeaseTTL
	}
	if conf.MaxLeaseTTL == 0 {
		conf.MaxLeaseTTL = maxLeaseTTL
	}
	if conf.DefaultLeaseTTL > conf.MaxLeaseTTL {
		return nil, fmt.Errorf("cannot have DefaultLeaseTTL larger than MaxLeaseTTL")
	}

	// Validate the advertise addr if its given to us
	if conf.RedirectAddr != "" {
		u, err := url.Parse(conf.RedirectAddr)
		if err != nil {
			return nil, fmt.Errorf("redirect address is not valid url: %w", err)
		}

		if u.Scheme == "" {
			return nil, fmt.Errorf("redirect address must include scheme (ex. 'http')")
		}
	}

	// Make a default logger if not provided
	if conf.Logger == nil {
		conf.Logger = logging.NewVaultLogger(log.Trace)
	}

	// Make a default metric sink if not provided
	if conf.MetricSink == nil {
		conf.MetricSink = metricsutil.BlackholeSink()
	}

	// Instantiate a non-nil raw config if none is provided
	if conf.RawConfig == nil {
		conf.RawConfig = new(server.Config)
	}

	// secureRandomReader cannot be nil
	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	clusterHeartbeatInterval := conf.ClusterHeartbeatInterval
	if clusterHeartbeatInterval == 0 {
		clusterHeartbeatInterval = 5 * time.Second
	}

	if conf.NumExpirationWorkers == 0 {
		conf.NumExpirationWorkers = numExpirationWorkersDefault
	}

	effectiveSDKVersion := conf.EffectiveSDKVersion
	if effectiveSDKVersion == "" {
		effectiveSDKVersion = version.GetVersion().Version
	}

	// Setup the core
	c := &Core{
		entCore:              entCore{},
		devToken:             conf.DevToken,
		physical:             conf.Physical,
		serviceRegistration:  conf.GetServiceRegistration(),
		underlyingPhysical:   conf.Physical,
		storageType:          conf.StorageType,
		redirectAddr:         conf.RedirectAddr,
		clusterAddr:          new(atomic.Value),
		clusterListener:      new(atomic.Value),
		customListenerHeader: new(atomic.Value),
		seal:                 conf.Seal,
		router:               NewRouter(),
		sealed:               new(uint32),
		sealMigrationDone:    new(uint32),
		standby:              true,
		standbyStopCh:        new(atomic.Value),
		baseLogger:           conf.Logger,
		logger:               conf.Logger.Named("core"),
		logLevel:             conf.LogLevel,

		defaultLeaseTTL:                conf.DefaultLeaseTTL,
		maxLeaseTTL:                    conf.MaxLeaseTTL,
		sentinelTraceDisabled:          conf.DisableSentinelTrace,
		cachingDisabled:                conf.DisableCache,
		clusterName:                    conf.ClusterName,
		clusterNetworkLayer:            conf.ClusterNetworkLayer,
		clusterPeerClusterAddrsCache:   cache.New(3*clusterHeartbeatInterval, time.Second),
		enableMlock:                    !conf.DisableMlock,
		rawEnabled:                     conf.EnableRaw,
		shutdownDoneCh:                 make(chan struct{}),
		replicationState:               new(uint32),
		atomicPrimaryClusterAddrs:      new(atomic.Value),
		atomicPrimaryFailoverAddrs:     new(atomic.Value),
		localClusterPrivateKey:         new(atomic.Value),
		localClusterCert:               new(atomic.Value),
		localClusterParsedCert:         new(atomic.Value),
		activeNodeReplicationState:     new(uint32),
		keepHALockOnStepDown:           new(uint32),
		replicationFailure:             new(uint32),
		disablePerfStandby:             true,
		activeContextCancelFunc:        new(atomic.Value),
		allLoggers:                     conf.AllLoggers,
		builtinRegistry:                conf.BuiltinRegistry,
		neverBecomeActive:              new(uint32),
		clusterLeaderParams:            new(atomic.Value),
		metricsHelper:                  conf.MetricsHelper,
		metricSink:                     conf.MetricSink,
		secureRandomReader:             conf.SecureRandomReader,
		rawConfig:                      new(atomic.Value),
		recoveryMode:                   conf.RecoveryMode,
		postUnsealStarted:              new(uint32),
		raftInfo:                       new(atomic.Value),
		raftJoinDoneCh:                 make(chan struct{}),
		clusterHeartbeatInterval:       clusterHeartbeatInterval,
		activityLogConfig:              conf.ActivityLogConfig,
		keyRotateGracePeriod:           new(int64),
		numExpirationWorkers:           conf.NumExpirationWorkers,
		raftFollowerStates:             raft.NewFollowerStates(),
		disableAutopilot:               conf.DisableAutopilot,
		enableResponseHeaderHostname:   conf.EnableResponseHeaderHostname,
		enableResponseHeaderRaftNodeID: conf.EnableResponseHeaderRaftNodeID,
		mountMigrationTracker:          &sync.Map{},
		disableSSCTokens:               conf.DisableSSCTokens,
		effectiveSDKVersion:            effectiveSDKVersion,
	}

	c.standbyStopCh.Store(make(chan struct{}))
	atomic.StoreUint32(c.sealed, 1)
	c.metricSink.SetGaugeWithLabels([]string{"core", "unsealed"}, 0, nil)

	c.allLoggers = append(c.allLoggers, c.logger)

	c.router.logger = c.logger.Named("router")
	c.allLoggers = append(c.allLoggers, c.router.logger)

	c.inFlightReqData = &InFlightRequests{
		InFlightReqMap:   &sync.Map{},
		InFlightReqCount: uberAtomic.NewUint64(0),
	}

	c.SetConfig(conf.RawConfig)

	atomic.StoreUint32(c.replicationState, uint32(consts.ReplicationDRDisabled|consts.ReplicationPerformanceDisabled))
	c.localClusterCert.Store(([]byte)(nil))
	c.localClusterParsedCert.Store((*x509.Certificate)(nil))
	c.localClusterPrivateKey.Store((*ecdsa.PrivateKey)(nil))

	c.clusterLeaderParams.Store((*ClusterLeaderParams)(nil))
	c.clusterAddr.Store(conf.ClusterAddr)
	c.activeContextCancelFunc.Store((context.CancelFunc)(nil))
	atomic.StoreInt64(c.keyRotateGracePeriod, int64(2*time.Minute))

	c.hcpLinkStatus = HCPLinkStatus{
		lock:             sync.RWMutex{},
		ConnectionStatus: "disconnected",
	}

	c.raftInfo.Store((*raftInformation)(nil))

	switch conf.ClusterCipherSuites {
	case "tls13", "tls12":
		// Do nothing, let Go use the default

	case "":
		// Add in forward compatible TLS 1.3 suites, followed by handpicked 1.2 suites
		c.clusterCipherSuites = []uint16{
			// 1.3
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			// 1.2
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		}

	default:
		suites, err := tlsutil.ParseCiphers(conf.ClusterCipherSuites)
		if err != nil {
			return nil, fmt.Errorf("error parsing cluster cipher suites: %w", err)
		}
		c.clusterCipherSuites = suites
	}

	// Load CORS config and provide a value for the core field.
	c.corsConfig = &CORSConfig{
		core:    c,
		Enabled: new(uint32),
	}

	if c.seal == nil {
		wrapper := aeadwrapper.NewShamirWrapper()
		wrapper.SetConfig(context.Background(), awskms.WithLogger(c.logger.Named("shamir")))

		c.seal = NewDefaultSeal(&vaultseal.Access{
			Wrapper: wrapper,
		})
	}
	c.seal.SetCore(c)
	return c, nil
}

// p1007
func NewCore(conf *CoreConfig) (*Core, error) {
	var err error
	c, err := CreateCore(conf)
	if err != nil {
		return nil, err
	}

	if err = coreInit(c, conf); err != nil {
		return nil, err
	}
	if !conf.DisableMlock {
		if err := mlock.LockMemory(); err != nil {
			return nil, fmt.Errorf(
				"Failed to lock memory: %v\n\n"+
					"This usually means that the mlock syscall is not available.\n"+
					"Vault uses mlock to prevent memory from being swapped to\n"+
					"disk. This requires root privileges as well as a machine\n"+
					"that supports mlock. Please enable mlock on your system or\n"+
					"disable Vault from using it. To disable Vault from using it,\n"+
					"set the `disable_mlock` configuration option in your configuration\n"+
					"file.",
				err)
		}
	}
	c.barrier, err = NewAESGCMBarrier(c.physical)
	if err != nil {
		return nil, fmt.Errorf("barrier setup failed: %w", err)
	}

	if err := storedLicenseCheck(c, conf); err != nil {
		return nil, err
	}

	conf.ReloadFuncsLock = &c.reloadFuncsLock
	c.reloadFuncsLock.Lock()
	c.reloadFuncs = make(map[string][]reloadutil.ReloadFunc)
	c.reloadFuncsLock.Unlock()
	conf.ReloadFuncs = &c.reloadFuncs

	c.rollbackPeriod = conf.RollbackPeriod
	if conf.RollbackPeriod == 0 {
		c.rollbackPeriod = time.Minute
	}

	if c.recoveryMode {
		panic("not implement")
	}

	if conf.PluginDirectory != "" {
		c.pluginDirectory, err = filepath.Abs(conf.PluginDirectory)
		if err != nil {
			return nil, fmt.Errorf("core setup failed, could not verify plugin directory: %w", err)
		}
	}

	if conf.PluginFileUid != 0 {
		c.pluginFileUid = conf.PluginFileUid
	}
	if conf.PluginFilePermissions != 0 {
		c.pluginFilePermissions = conf.PluginFilePermissions
	}

	createSecondaries(c, conf)

	if conf.HAPhysical != nil && conf.HAPhysical.HAEnabled() {
		c.ha = conf.HAPhysical
	}

	c.loginMFABackend = NewLoginMFABackend(c, conf.Logger)

	if c.loginMFABackend.mfaLogger != nil {
		c.AddLogger(c.loginMFABackend.mfaLogger)
	}

	logicalBackends := make(map[string]logical.Factory)
	for k, f := range conf.LogicalBackends {
		logicalBackends[k] = f
	}
	_, ok := logicalBackends["kv"]
	if !ok {
		panic("not implement")
	}

	logicalBackends["cubbyhole"] = CubbyholeBackendFactory
	logicalBackends[systemMountType] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
		panic("not implement")
	}
	logicalBackends["identity"] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
		panic("not implement")
	}
	addExtraLogicalBackends(c, logicalBackends)
	c.logicalBackends = logicalBackends

	credentialBackends := make(map[string]logical.Factory)
	for k, f := range conf.CredentialBackends {
		credentialBackends[k] = f
	}
	credentialBackends["token"] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
		panic("not implement")
	}
	addExtraCredentialBackends(c, credentialBackends)
	c.credentialBackends = credentialBackends

	auditBackends := make(map[string]audit.Factory)
	for k, f := range conf.AuditBackends {
		auditBackends[k] = f
	}
	c.auditBackends = auditBackends

	uiStoragePrefix := systemBarrierPrefix + "ui"
	c.uiConfig = NewUIConfig(conf.EnableUI, physical.NewView(c.physical, uiStoragePrefix), NewBarrierView(c.barrier, uiStoragePrefix))

	c.clusterListener.Store((*cluster.Listener)(nil))

	// for listeners with custom response headers, configuring customListenerHeader
	if conf.RawConfig.Listeners != nil {
		uiHeaders, err := c.UIHeaders()
		if err != nil {
			return nil, err
		}
		c.customListenerHeader.Store(NewListenerCustomHeader(conf.RawConfig.Listeners, c.logger, uiHeaders))
	} else {
		c.customListenerHeader.Store(([]*ListenerCustomHeaders)(nil))
	}

	logRequestsLevel := conf.RawConfig.LogRequestsLevel
	c.logRequestsLevel = uberAtomic.NewInt32(0)
	switch {
	case log.LevelFromString(logRequestsLevel) > log.NoLevel && log.LevelFromString(logRequestsLevel) < log.Off:
		c.logRequestsLevel.Store(int32(log.LevelFromString(logRequestsLevel)))
	case logRequestsLevel != "":
		c.logger.Warn("invalid log_requests_level", "level", conf.RawConfig.LogRequestsLevel)
	}

	quotasLogger := conf.Logger.Named("quotas")
	c.allLoggers = append(c.allLoggers, quotasLogger)
	c.quotaManager, err = quotas.NewManager(quotasLogger, c.quotaLeaseWalker, c.metricSink)
	if err != nil {
		return nil, err
	}

	err = c.adjustForSealMigration(conf.UnwrapSeal)
	if err != nil {
		return nil, err
	}

	if c.versionHistory == nil {
		c.logger.Info("Initializing version history cache for core")
		c.versionHistory = make(map[string]VaultVersion)
	}

	return c, nil
}

// p1254
func (c *Core) CORSConfig() *CORSConfig {
	return c.corsConfig
}

func (c *Core) GetContext() (context.Context, context.CancelFunc) {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	return context.WithCancel(namespace.RootContext(c.activeContext))
}

// p1986
func (c *Core) UIHeaders() (http.Header, error) {
	return c.uiConfig.Headers(context.Background())
}

// p2514
func (c *Core) PhysicalSealConfigs(ctx context.Context) (*SealConfig, *SealConfig, error) {
	pe, err := c.physical.Get(ctx, barrierSealConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch barrier seal configuration at migration check time: %w", err)
	}
	if pe == nil {
		return nil, nil, nil
	}

	barrierConf := new(SealConfig)

	if err := jsonutil.DecodeJSON(pe.Value, barrierConf); err != nil {
		return nil, nil, fmt.Errorf("failed to decode barrier seal configuration at migration check time: %w", err)
	}
	err = barrierConf.Validate()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate barrier seal configuration at migration check time: %w", err)
	}
	// In older versions of vault the default seal would not store a type. This
	// is here to offer backwards compatibility for older seal configs.
	if barrierConf.Type == "" {
		barrierConf.Type = wrapping.WrapperTypeShamir.String()
	}

	var recoveryConf *SealConfig
	pe, err = c.physical.Get(ctx, recoverySealConfigPlaintextPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch seal configuration at migration check time: %w", err)
	}
	if pe != nil {
		recoveryConf = &SealConfig{}
		if err := jsonutil.DecodeJSON(pe.Value, recoveryConf); err != nil {
			return nil, nil, fmt.Errorf("failed to decode seal configuration at migration check time: %w", err)
		}
		err = recoveryConf.Validate()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to validate seal configuration at migration check time: %w", err)
		}
		// In older versions of vault the default seal would not store a type. This
		// is here to offer backwards compatibility for older seal configs.
		if recoveryConf.Type == "" {
			recoveryConf.Type = wrapping.WrapperTypeShamir.String()
		}
	}

	return barrierConf, recoveryConf, nil
}

// p2581
func (c *Core) adjustForSealMigration(unwrapSeal Seal) error {
	ctx := context.Background()
	existBarrierSealConfig, existRecoverySealConfig, err := c.PhysicalSealConfigs(ctx)
	if err != nil {
		return fmt.Errorf("Error checking for existing seal: %s", err)
	}

	if existBarrierSealConfig == nil || existBarrierSealConfig.Type == WrapperTypeHsmAutoDeprecated.String() {
		return nil
	}

	if unwrapSeal == nil {
		switch {
		case existBarrierSealConfig.Type == c.seal.BarrierType().String():
			return nil
		case c.seal.BarrierType() == wrapping.WrapperTypeShamir:
			return fmt.Errorf("cannot seal migrate from %q to Shamir, no disabled seal in configuration",
				existBarrierSealConfig.Type)
		case existBarrierSealConfig.Type == wrapping.WrapperTypeShamir.String():
			unwrapSeal = NewDefaultSeal(&vaultseal.Access{
				Wrapper: aeadwrapper.NewShamirWrapper(),
			})
		default:
			return fmt.Errorf("cannot seal migrate from %q to %q, no disabled seal in configuration",
				existBarrierSealConfig.Type, c.seal.BarrierType())
		}
	} else {
		if unwrapSeal.BarrierType() == wrapping.WrapperTypeShamir {
			return errors.New("Shamir seals cannot be set disabled (they should simply not be set)")
		}
	}

	unwrapSeal.SetCore(c)

	if existBarrierSealConfig.Type != wrapping.WrapperTypeShamir.String() && existRecoverySealConfig == nil {
		entry, err := c.physical.Get(ctx, recoverySealConfigPath)
		if err != nil {
			return fmt.Errorf("failed to read %q recovery seal configuration: %w", existBarrierSealConfig.Type, err)
		}
		if entry == nil {
			return errors.New("Recovery seal configuration not found for existing seal")
		}
		return errors.New("Cannot migrate seals while using a legacy recovery seal config")
	}

	c.migrationInfo = &migrationInformation{
		seal: unwrapSeal,
	}
	if existBarrierSealConfig.Type != c.seal.BarrierType().String() {
		c.adjustSealConfigDuringMigration(existBarrierSealConfig, existRecoverySealConfig)
	}
	c.initSealsForMigration()
	c.logger.Warn("entering seal migration mode; Vault will not automatically unseal even if using an autoseal", "from_barrier_type", c.migrationInfo.seal.BarrierType(), "to_barrier_type", c.seal.BarrierType())

	return nil
}

// p2709
func (c *Core) adjustSealConfigDuringMigration(existBarrierSealConfig, existRecoverySealConfig *SealConfig) {
	switch {
	case c.migrationInfo.seal.RecoveryKeySupported() && existRecoverySealConfig != nil:
		newSealConfig := existRecoverySealConfig.Clone()
		newSealConfig.StoredShares = 1
		c.seal.SetCachedBarrierConfig(newSealConfig)
	case !c.migrationInfo.seal.RecoveryKeySupported() && c.seal.RecoveryKeySupported():
		newBarrierSealConfig := &SealConfig{
			Type:            c.seal.BarrierType().String(),
			SecretShares:    1,
			SecretThreshold: 1,
			StoredShares:    1,
		}
		c.seal.SetCachedBarrierConfig(newBarrierSealConfig)

		newRecoveryConfig := existBarrierSealConfig.Clone()
		newRecoveryConfig.StoredShares = 0
		c.seal.SetCachedRecoveryConfig(newRecoveryConfig)
	}
}

// p2817
func (c *Core) IsInSealMigrationMode() bool {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	return c.migrationInfo != nil
}

// p2857
func (c *Core) AddLogger(logger log.Logger) {
	c.allLoggersLock.Lock()
	defer c.allLoggersLock.Unlock()
	c.allLoggers = append(c.allLoggers, logger)
}

// p2885
func (c *Core) SetConfig(conf *server.Config) {
	c.rawConfig.Store(conf)
	bz, err := json.Marshal(c.SanitizedConfig())
	if err != nil {
		c.logger.Error("error serializing sanitized config", "error", err)
		return
	}

	c.logger.Debug("set config", "sanitized config", string(bz))
}

// p2959
func (c *Core) SanitizedConfig() map[string]interface{} {
	conf := c.rawConfig.Load()
	if conf == nil {
		return nil
	}
	return conf.(*server.Config).Sanitized()
}

// p2980
func (c *Core) MetricSink() *metricsutil.ClusterMetricSink {
	return c.metricSink
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
