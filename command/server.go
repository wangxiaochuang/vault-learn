package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	vaulthttp "github.com/hashicorp/vault/http"

	"github.com/hashicorp/vault/internalshared/listenerutil"

	aeadwrapper "github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
	"github.com/hashicorp/vault/helper/builtinplugins"

	vaultseal "github.com/hashicorp/vault/vault/seal"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-secure-stdlib/gatedwriter"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/command/server"
	"github.com/hashicorp/vault/helper/constants"
	"github.com/hashicorp/vault/helper/metricsutil"
	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/useragent"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/sdk/version"
	sr "github.com/hashicorp/vault/serviceregistration"
	"github.com/hashicorp/vault/vault"
	"github.com/hashicorp/vault/wxc"
	"github.com/posener/complete"
	"golang.org/x/net/http/httpproxy"
	"google.golang.org/grpc/grpclog"
)

var memProfilerEnabled = false

var enableFourClusterDev = func(c *ServerCommand, base *vault.CoreConfig, info map[string]string, infoKeys []string, devListenAddress, tempDir string) int {
	c.logger.Error("-dev-four-cluster only supported in enterprise Vault")
	return 1
}

const (
	storageMigrationLock = "core/migration"

	storageTypeRaft            = "raft"
	storageTypeConsul          = "consul"
	disableStorageTypeCheckEnv = "VAULT_DISABLE_SUPPORTED_STORAGE_CHECK"
)

type ServerCommand struct {
	*BaseCommand

	AuditBackends      map[string]audit.Factory
	CredentialBackends map[string]logical.Factory
	LogicalBackends    map[string]logical.Factory
	PhysicalBackends   map[string]physical.Factory

	ServiceRegistrations map[string]sr.Factory

	ShutdownCh chan struct{}
	SighupCh   chan struct{}
	SigUSR2Ch  chan struct{}

	WaitGroup *sync.WaitGroup

	logOutput   io.Writer
	gatedWriter *gatedwriter.Writer
	logger      hclog.InterceptLogger

	cleanupGuard sync.Once

	reloadFuncsLock   *sync.RWMutex
	reloadFuncs       *map[string][]reloadutil.ReloadFunc
	startedCh         chan (struct{}) // for tests
	reloadedCh        chan (struct{}) // for tests
	licenseReloadedCh chan (error)    // for tests

	allLoggers []hclog.Logger

	// new stuff
	flagConfigs            []string
	flagLogLevel           string
	flagLogFormat          string
	flagRecovery           bool
	flagDev                bool
	flagDevTLS             bool
	flagDevTLSCertDir      string
	flagDevRootTokenID     string
	flagDevListenAddr      string
	flagDevNoStoreToken    bool
	flagDevPluginDir       string
	flagDevPluginInit      bool
	flagDevHA              bool
	flagDevLatency         int
	flagDevLatencyJitter   int
	flagDevLeasedKV        bool
	flagDevKVV1            bool
	flagDevSkipInit        bool
	flagDevThreeNode       bool
	flagDevFourCluster     bool
	flagDevTransactional   bool
	flagDevAutoSeal        bool
	flagTestVerifyOnly     bool
	flagCombineLogs        bool
	flagTestServerConfig   bool
	flagDevConsul          bool
	flagExitOnCoreShutdown bool
	flagDiagnose           string
}

func (c *ServerCommand) Synopsis() string {
	return "Start a Vault server"
}

func (c *ServerCommand) Help() string {
	helpText := `
Usage: vault server [options]

  This command starts a Vault server that responds to API requests. By default,
  Vault will start in a "sealed" state. The Vault cluster must be initialized
  before use, usually by the "vault operator init" command. Each Vault server must
  also be unsealed using the "vault operator unseal" command or the API before the
  server can respond to requests.

  Start a server with a configuration file:

      $ vault server -config=/etc/vault/config.hcl

  Run in "dev" mode:

      $ vault server -dev -dev-root-token-id="root"

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

// p175
func (c *ServerCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)

	f := set.NewFlagSet("Command Options")

	f.StringSliceVar(&StringSliceVar{
		Name:   "config",
		Target: &c.flagConfigs,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
			complete.PredictDirs("*"),
		),
		Usage: "Path to a configuration file or directory of configuration " +
			"files. This flag can be specified multiple times to load multiple " +
			"configurations. If the path is a directory, all files which end in " +
			".hcl or .json are loaded.",
	})

	f.StringVar(&StringVar{
		Name:       "log-level",
		Target:     &c.flagLogLevel,
		Default:    notSetValue,
		EnvVar:     "VAULT_LOG_LEVEL",
		Completion: complete.PredictSet("trace", "debug", "info", "warn", "error"),
		Usage: "Log verbosity level. Supported values (in order of detail) are " +
			"\"trace\", \"debug\", \"info\", \"warn\", and \"error\".",
	})

	f.StringVar(&StringVar{
		Name:    "log-format",
		Target:  &c.flagLogFormat,
		Default: notSetValue,
		// EnvVar can't be just "VAULT_LOG_FORMAT", because more than one env var name is supported
		// for backwards compatibility reasons.
		// See github.com/hashicorp/vault/sdk/helper/logging.ParseEnvLogFormat()
		Completion: complete.PredictSet("standard", "json"),
		Usage:      `Log format. Supported values are "standard" and "json".`,
	})

	f.BoolVar(&BoolVar{
		Name:    "exit-on-core-shutdown",
		Target:  &c.flagExitOnCoreShutdown,
		Default: false,
		Usage:   "Exit the vault server if the vault core is shutdown.",
	})

	f.BoolVar(&BoolVar{
		Name:   "recovery",
		Target: &c.flagRecovery,
		Usage: "Enable recovery mode. In this mode, Vault is used to perform recovery actions." +
			"Using a recovery operation token, \"sys/raw\" API can be used to manipulate the storage.",
	})

	// Disabled by default until functional
	if os.Getenv(OperatorDiagnoseEnableEnv) != "" {
		f.StringVar(&StringVar{
			Name:    "diagnose",
			Target:  &c.flagDiagnose,
			Default: notSetValue,
			Usage:   "Run diagnostics before starting Vault. Specify a filename to direct output to that file.",
		})
	} else {
		// Ensure diagnose is *not* run when feature flag is off.
		c.flagDiagnose = notSetValue
	}

	f = set.NewFlagSet("Dev Options")

	f.BoolVar(&BoolVar{
		Name:   "dev",
		Target: &c.flagDev,
		Usage: "Enable development mode. In this mode, Vault runs in-memory and " +
			"starts unsealed. As the name implies, do not run \"dev\" mode in " +
			"production.",
	})

	f.BoolVar(&BoolVar{
		Name:   "dev-tls",
		Target: &c.flagDevTLS,
		Usage: "Enable TLS development mode. In this mode, Vault runs in-memory and " +
			"starts unsealed, with a generated TLS CA, certificate and key. " +
			"As the name implies, do not run \"dev-tls\" mode in " +
			"production.",
	})

	f.StringVar(&StringVar{
		Name:    "dev-tls-cert-dir",
		Target:  &c.flagDevTLSCertDir,
		Default: "",
		Usage: "Directory where generated TLS files are created if `-dev-tls` is " +
			"specified. If left unset, files are generated in a temporary directory.",
	})

	f.StringVar(&StringVar{
		Name:    "dev-root-token-id",
		Target:  &c.flagDevRootTokenID,
		Default: "",
		EnvVar:  "VAULT_DEV_ROOT_TOKEN_ID",
		Usage: "Initial root token. This only applies when running in \"dev\" " +
			"mode.",
	})

	f.StringVar(&StringVar{
		Name:    "dev-listen-address",
		Target:  &c.flagDevListenAddr,
		Default: "127.0.0.1:8200",
		EnvVar:  "VAULT_DEV_LISTEN_ADDRESS",
		Usage:   "Address to bind to in \"dev\" mode.",
	})
	f.BoolVar(&BoolVar{
		Name:    "dev-no-store-token",
		Target:  &c.flagDevNoStoreToken,
		Default: false,
		Usage: "Do not persist the dev root token to the token helper " +
			"(usually the local filesystem) for use in future requests. " +
			"The token will only be displayed in the command output.",
	})

	// Internal-only flags to follow.
	//
	// Why hello there little source code reader! Welcome to the Vault source
	// code. The remaining options are intentionally undocumented and come with
	// no warranty or backwards-compatibility promise. Do not use these flags
	// in production. Do not build automation using these flags. Unless you are
	// developing against Vault, you should not need any of these flags.

	f.StringVar(&StringVar{
		Name:       "dev-plugin-dir",
		Target:     &c.flagDevPluginDir,
		Default:    "",
		Completion: complete.PredictDirs("*"),
		Hidden:     true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-plugin-init",
		Target:  &c.flagDevPluginInit,
		Default: true,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-ha",
		Target:  &c.flagDevHA,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-transactional",
		Target:  &c.flagDevTransactional,
		Default: false,
		Hidden:  true,
	})

	f.IntVar(&IntVar{
		Name:   "dev-latency",
		Target: &c.flagDevLatency,
		Hidden: true,
	})

	f.IntVar(&IntVar{
		Name:   "dev-latency-jitter",
		Target: &c.flagDevLatencyJitter,
		Hidden: true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-leased-kv",
		Target:  &c.flagDevLeasedKV,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-kv-v1",
		Target:  &c.flagDevKVV1,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-auto-seal",
		Target:  &c.flagDevAutoSeal,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-skip-init",
		Target:  &c.flagDevSkipInit,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-three-node",
		Target:  &c.flagDevThreeNode,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-four-cluster",
		Target:  &c.flagDevFourCluster,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-consul",
		Target:  &c.flagDevConsul,
		Default: false,
		Hidden:  true,
	})

	// TODO: should the below flags be public?
	f.BoolVar(&BoolVar{
		Name:    "combine-logs",
		Target:  &c.flagCombineLogs,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "test-verify-only",
		Target:  &c.flagTestVerifyOnly,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "test-server-config",
		Target:  &c.flagTestServerConfig,
		Default: false,
		Hidden:  true,
	})

	// End internal-only flags.

	return set
}

func (c *ServerCommand) flushLog() {
	c.logger.(hclog.OutputResettable).ResetOutputWithFlush(&hclog.LoggerOptions{
		Output: c.logOutput,
	}, c.gatedWriter)
}

// p433
func (c *ServerCommand) parseConfig() (*server.Config, []configutil.ConfigError, error) {
	var configErrors []configutil.ConfigError
	// Load the configuration
	var config *server.Config
	for _, path := range c.flagConfigs {
		current, err := server.LoadConfig(path)
		if err != nil {
			return nil, nil, fmt.Errorf("error loading configuration from %s: %w", path, err)
		}

		configErrors = append(configErrors, current.Validate(path)...)

		if config == nil {
			config = current
		} else {
			config = config.Merge(current)
		}
	}

	if config != nil && config.Entropy != nil && config.Entropy.Mode == configutil.EntropyAugmentation && constants.IsFIPS() {
		c.UI.Warn("WARNING: Entropy Augmentation is not supported in FIPS 140-2 Inside mode; disabling from server configuration!\n")
		config.Entropy = nil
	}

	return config, configErrors, nil
}

// p773
func logProxyEnvironmentVariables(logger hclog.Logger) {
	proxyCfg := httpproxy.FromEnvironment()
	cfgMap := map[string]string{
		"http_proxy":  proxyCfg.HTTPProxy,
		"https_proxy": proxyCfg.HTTPSProxy,
		"no_proxy":    proxyCfg.NoProxy,
	}
	for k, v := range cfgMap {
		u, err := url.Parse(v)
		if err != nil {
			// Env vars may contain URLs or host:port values.  We only care
			// about the former.
			continue
		}
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword("redacted-username", "redacted-password")
		} else if user := u.User.Username(); user != "" {
			u.User = url.User("redacted-username")
		}
		cfgMap[k] = u.String()
	}
	logger.Info("proxy environment", "http_proxy", cfgMap["http_proxy"],
		"https_proxy", cfgMap["https_proxy"], "no_proxy", cfgMap["no_proxy"])
}

// p798
func (c *ServerCommand) adjustLogLevel(config *server.Config, logLevelWasNotSet bool) (string, error) {
	var logLevelString string
	if config.LogLevel != "" && logLevelWasNotSet {
		configLogLevel := strings.ToLower(strings.TrimSpace(config.LogLevel))
		logLevelString = configLogLevel
		switch configLogLevel {
		case "trace":
			c.logger.SetLevel(hclog.Trace)
		case "debug":
			c.logger.SetLevel(hclog.Debug)
		case "notice", "info", "":
			c.logger.SetLevel(hclog.Info)
		case "warn", "warning":
			c.logger.SetLevel(hclog.Warn)
		case "err", "error":
			c.logger.SetLevel(hclog.Error)
		default:
			return "", fmt.Errorf("unknown log level: %s", config.LogLevel)
		}
	}
	return logLevelString, nil
}

// p821
func (c *ServerCommand) processLogLevelAndFormat(config *server.Config) (hclog.Level, string, bool, logging.LogFormat, error) {
	// Create a logger. We wrap it in a gated writer so that it doesn't
	// start logging too early.
	c.logOutput = os.Stderr
	if c.flagCombineLogs {
		c.logOutput = os.Stdout
	}
	c.gatedWriter = gatedwriter.NewWriter(c.logOutput)
	var level hclog.Level
	var logLevelWasNotSet bool
	logFormat := logging.UnspecifiedFormat
	logLevelString := c.flagLogLevel
	c.flagLogLevel = strings.ToLower(strings.TrimSpace(c.flagLogLevel))
	switch c.flagLogLevel {
	case notSetValue, "":
		logLevelWasNotSet = true
		logLevelString = "info"
		level = hclog.Info
	case "trace":
		level = hclog.Trace
	case "debug":
		level = hclog.Debug
	case "notice", "info":
		level = hclog.Info
	case "warn", "warning":
		level = hclog.Warn
	case "err", "error":
		level = hclog.Error
	default:
		return level, logLevelString, logLevelWasNotSet, logFormat, fmt.Errorf("unknown log level: %s", c.flagLogLevel)
	}

	if c.flagLogFormat != notSetValue {
		var err error
		logFormat, err = logging.ParseLogFormat(c.flagLogFormat)
		if err != nil {
			return level, logLevelString, logLevelWasNotSet, logFormat, err
		}
	}
	if logFormat == logging.UnspecifiedFormat {
		logFormat = logging.ParseEnvLogFormat()
	}
	if logFormat == logging.UnspecifiedFormat {
		var err error
		logFormat, err = logging.ParseLogFormat(config.LogFormat)
		if err != nil {
			return level, logLevelString, logLevelWasNotSet, logFormat, err
		}
	}

	return level, logLevelString, logLevelWasNotSet, logFormat, nil
}

// p882
func (c *ServerCommand) setupStorage(config *server.Config) (physical.Backend, error) {
	if config.Storage == nil {
		return nil, errors.New("A storage backend must be specified")
	}

	factory, exists := c.PhysicalBackends[config.Storage.Type]
	if !exists {
		return nil, fmt.Errorf("Unknown storage type %s", config.Storage.Type)
	}

	switch config.Storage.Type {
	case storageTypeConsul:
		panic("not implement")
	case storageTypeRaft:
		panic("not implement")
	}

	namedStorageLogger := c.logger.Named("storage." + config.Storage.Type)
	c.allLoggers = append(c.allLoggers, namedStorageLogger)
	backend, err := factory(config.Storage.Config, namedStorageLogger)
	if err != nil {
		return nil, fmt.Errorf("Error initializing storage of type %s: %w", config.Storage.Type, err)
	}

	return backend, nil
}

// p953
func (c *ServerCommand) InitListeners(config *server.Config, disableClustering bool, infoKeys *[]string, info *map[string]string) (int, []listenerutil.Listener, []*net.TCPAddr, error) {
	clusterAddrs := []*net.TCPAddr{}

	// Initialize the listeners
	lns := make([]listenerutil.Listener, 0, len(config.Listeners))

	c.reloadFuncsLock.Lock()

	defer c.reloadFuncsLock.Unlock()

	var errMsg error
	for i, lnConfig := range config.Listeners {
		ln, props, reloadFunc, err := server.NewListener(lnConfig, c.gatedWriter, c.UI)
		if err != nil {
			errMsg = fmt.Errorf("Error initializing listener of type %s: %s", lnConfig.Type, err)
			return 1, nil, nil, errMsg
		}

		if reloadFunc != nil {
			relSlice := (*c.reloadFuncs)["listener|"+lnConfig.Type]
			relSlice = append(relSlice, reloadFunc)
			(*c.reloadFuncs)["listener|"+lnConfig.Type] = relSlice
		}

		if !disableClustering && lnConfig.Type == "tcp" {
			addr := lnConfig.ClusterAddress
			if addr != "" {
				tcpAddr, err := net.ResolveTCPAddr("tcp", lnConfig.ClusterAddress)
				if err != nil {
					errMsg = fmt.Errorf("Error resolving cluster_address: %s", err)
					return 1, nil, nil, errMsg
				}
				clusterAddrs = append(clusterAddrs, tcpAddr)
			} else {
				tcpAddr, ok := ln.Addr().(*net.TCPAddr)
				if !ok {
					errMsg = fmt.Errorf("Failed to parse tcp listener")
					return 1, nil, nil, errMsg
				}
				clusterAddr := &net.TCPAddr{
					IP:   tcpAddr.IP,
					Port: tcpAddr.Port + 1,
				}
				clusterAddrs = append(clusterAddrs, clusterAddr)
				addr = clusterAddr.String()
			}
			props["cluster address"] = addr
		}

		if lnConfig.MaxRequestSize == 0 {
			lnConfig.MaxRequestSize = vaulthttp.DefaultMaxRequestSize
		}
		props["max_request_size"] = fmt.Sprintf("%d", lnConfig.MaxRequestSize)

		if lnConfig.MaxRequestDuration == 0 {
			lnConfig.MaxRequestDuration = vault.DefaultMaxRequestDuration
		}
		props["max_request_duration"] = lnConfig.MaxRequestDuration.String()

		lns = append(lns, listenerutil.Listener{
			Listener: ln,
			Config:   lnConfig,
		})

		// Store the listener props for output later
		key := fmt.Sprintf("listener %d", i+1)
		propsList := make([]string, 0, len(props))
		for k, v := range props {
			propsList = append(propsList, fmt.Sprintf(
				"%s: %q", k, v))
		}
		sort.Strings(propsList)
		*infoKeys = append(*infoKeys, key)
		(*info)[key] = fmt.Sprintf(
			"%s (%s)", lnConfig.Type, strings.Join(propsList, ", "))

	}
	if !disableClustering {
		if c.logger.IsDebug() {
			c.logger.Debug("cluster listener addresses synthesized", "cluster_addresses", clusterAddrs)
		}
	}
	return 0, lns, clusterAddrs, nil
}

// p1038
func (c *ServerCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if c.flagRecovery {
		panic("not implement")
	}
	if c.flagDevConsul || c.flagDevHA || c.flagDevTransactional || c.flagDevLeasedKV || c.flagDevThreeNode || c.flagDevFourCluster || c.flagDevAutoSeal || c.flagDevKVV1 || c.flagDevTLS {
		c.flagDev = true
	}
	if !c.flagDev {
		switch {
		case len(c.flagConfigs) == 0:
			c.UI.Error("Must specify at least one config path using -config")
			return 1
		case c.flagDevRootTokenID != "":
			c.UI.Warn(wrapAtLength(
				"You cannot specify a custom root token ID outside of \"dev\" mode. " +
					"Your request has been ignored."))
			c.flagDevRootTokenID = ""
		}
	}

	if c.flagDiagnose != notSetValue {
		panic("not implement")
	}

	var config *server.Config
	var err error
	// var certDir string
	if c.flagDev {
		var devStorageType string
		switch {
		case c.flagDevConsul:
			devStorageType = "consul"
		case c.flagDevHA && c.flagDevTransactional:
			devStorageType = "inmem_transactional_ha"
		case !c.flagDevHA && c.flagDevTransactional:
			devStorageType = "inmem_transactional"
		case c.flagDevHA && !c.flagDevTransactional:
			devStorageType = "inmem_ha"
		default:
			devStorageType = "inmem"
		}

		if c.flagDevTLS {
			panic("not implement")
		} else {
			config, err = server.DevConfig(devStorageType)
		}

		if err != nil {
			c.UI.Error(err.Error())
			return 1
		}

		if c.flagDevListenAddr != "" {
			config.Listeners[0].Address = c.flagDevListenAddr
		}
		config.Listeners[0].Telemetry.UnauthenticatedMetricsAccess = true
	}

	parsedConfig, configErrors, err := c.parseConfig()
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if config == nil {
		config = parsedConfig
	} else {
		config = config.Merge(parsedConfig)
	}

	if config == nil {
		c.UI.Output(wrapAtLength(
			"No configuration files found. Please provide configurations with the " +
				"-config flag. If you are supplying the path to a directory, please " +
				"ensure the directory contains files with the .hcl or .json " +
				"extension."))
		return 1
	}

	level, logLevelString, logLevelWasNotSet, logFormat, err := c.processLogLevelAndFormat(config)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	config.LogFormat = logFormat.String()

	if c.flagDevThreeNode || c.flagDevFourCluster {
		panic("not implement")
	} else {
		c.logger = hclog.NewInterceptLogger(&hclog.LoggerOptions{
			Output:            c.gatedWriter,
			Level:             level,
			IndependentLevels: true,
			// Note that if logFormat is either unspecified or standard, then
			// the resulting logger's format will be standard.
			JSONFormat: logFormat == logging.JSONFormat,
		})
	}

	for _, cErr := range configErrors {
		c.logger.Warn(cErr.String())
	}

	defer c.flushLog()

	c.allLoggers = []hclog.Logger{c.logger}

	logLevelStr, err := c.adjustLogLevel(config, logLevelWasNotSet)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if logLevelStr != "" {
		logLevelString = logLevelStr
	}

	// create GRPC logger
	namedGRPCLogFaker := c.logger.Named("grpclogfaker")
	c.allLoggers = append(c.allLoggers, namedGRPCLogFaker)
	grpclog.SetLogger(&grpclogFaker{
		logger: namedGRPCLogFaker,
		log:    os.Getenv("VAULT_GRPC_LOGGING") != "",
	})

	if memProfilerEnabled {
		// c.startMemProfiler()
		panic("not implement")
	}

	if config.DefaultMaxRequestDuration != 0 {
		vault.DefaultMaxRequestDuration = config.DefaultMaxRequestDuration
	}

	logProxyEnvironmentVariables(c.logger)

	if envMlock := os.Getenv("VAULT_DISABLE_MLOCK"); envMlock != "" {
		var err error
		config.DisableMlock, err = strconv.ParseBool(envMlock)
		if err != nil {
			c.UI.Output("Error parsing the environment variable VAULT_DISABLE_MLOCK")
			return 1
		}
	}

	if envLicensePath := os.Getenv(EnvVaultLicensePath); envLicensePath != "" {
		config.LicensePath = envLicensePath
	}
	if envLicense := os.Getenv(EnvVaultLicense); envLicense != "" {
		config.License = envLicense
	}
	if disableSSC := os.Getenv(DisableSSCTokens); disableSSC != "" {
		var err error
		config.DisableSSCTokens, err = strconv.ParseBool(disableSSC)
		if err != nil {
			c.UI.Warn(wrapAtLength("WARNING! failed to parse " +
				"VAULT_DISABLE_SERVER_SIDE_CONSISTENT_TOKENS env var: " +
				"setting to default value false"))
		}
	}

	if allowPendingRemoval := os.Getenv(consts.VaultAllowPendingRemovalMountsEnv); allowPendingRemoval != "" {
		var err error
		vault.PendingRemovalMountsAllowed, err = strconv.ParseBool(allowPendingRemoval)
		if err != nil {
			c.UI.Warn(wrapAtLength("WARNING! failed to parse " +
				consts.VaultAllowPendingRemovalMountsEnv + " env var: " +
				"defaulting to false."))
		}
	}

	if !c.flagDev && !config.DisableMlock && !mlock.Supported() {
		c.UI.Warn(wrapAtLength(
			"WARNING! mlock is not supported on this system! An mlockall(2)-like " +
				"syscall to prevent memory from being swapped to disk is not " +
				"supported on this system. For better security, only run Vault on " +
				"systems where this call is supported. If you are running Vault " +
				"in a Docker container, provide the IPC_LOCK cap to the container."))
	}

	inmemMetrics, metricSink, prometheusEnabled, err := configutil.SetupTelemetry(&configutil.SetupTelemetryOpts{
		Config:      config.Telemetry,
		Ui:          c.UI,
		ServiceName: "vault",
		DisplayName: "Vault",
		UserAgent:   useragent.String(),
		ClusterName: config.ClusterName,
	})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing telemetry: %s", err))
		return 1
	}

	metricsHelper := metricsutil.NewMetricsHelper(inmemMetrics, prometheusEnabled)

	backend, err := c.setupStorage(config)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if c.storageMigrationActive(backend) {
		return 1
	}

	var configSR sr.ServiceRegistration
	if config.ServiceRegistration != nil {
		panic("not implement")
	}

	infoKeys := make([]string, 0, 10)
	info := make(map[string]string)
	info["log level"] = logLevelString
	infoKeys = append(infoKeys, "log level")
	barrierSeal, barrierWrapper, unwrapSeal, seals, _, err := setSeal(c, config, infoKeys, info)
	// Check error here
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if seals != nil {
		for _, seal := range seals {
			// Ensure that the seal finalizer is called, even if using verify-only
			defer func(seal *vault.Seal) {
				err = (*seal).Finalize(context.Background())
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error finalizing seals: %v", err))
				}
			}(&seal)
		}
	}

	if barrierSeal == nil {
		c.UI.Error("Could not create barrier seal! Most likely proper Seal configuration information was not set, but no error was generated.")
		return 1
	}

	secureRandomReader, err := configutil.CreateSecureRandomReaderFunc(config.SharedConfig, barrierWrapper)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	coreConfig := createCoreConfig(c, config, backend, configSR, barrierSeal, unwrapSeal, metricsHelper, metricSink, secureRandomReader)
	if c.flagDevThreeNode {
		panic("not implement")
		// return c.enableThreeNodeDevCluster(&coreConfig, info, infoKeys, c.flagDevListenAddr, os.Getenv("VAULT_DEV_TEMP_DIR"))
	}

	if c.flagDevFourCluster {
		return enableFourClusterDev(c, &coreConfig, info, infoKeys, c.flagDevListenAddr, os.Getenv("VAULT_DEV_TEMP_DIR"))
	}

	disableClustering, err := initHaBackend(c, config, &coreConfig, backend)
	if err != nil {
		c.UI.Output(err.Error())
		return 1
	}

	err = determineRedirectAddr(c, &coreConfig, config)
	if err != nil {
		c.UI.Output(err.Error())
	}

	err = findClusterAddress(c, &coreConfig, config, disableClustering)
	if err != nil {
		c.UI.Output(err.Error())
		return 1
	}

	if enableUI := os.Getenv("VAULT_UI"); enableUI != "" {
		var err error
		coreConfig.EnableUI, err = strconv.ParseBool(enableUI)
		if err != nil {
			c.UI.Output("Error parsing the environment variable VAULT_UI")
			return 1
		}
	}

	isBackendHA := coreConfig.HAPhysical != nil && coreConfig.HAPhysical.HAEnabled()
	if !c.flagDev && (coreConfig.GetServiceRegistration() != nil) && !isBackendHA {
		c.UI.Output("service_registration is configured, but storage does not support HA")
		return 1
	}

	adjustCoreConfigForEnt(config, &coreConfig)

	if !c.flagDev && os.Getenv(disableStorageTypeCheckEnv) == "" {
		panic("not implement")
	}

	core, newCoreError := vault.NewCore(&coreConfig)
	if newCoreError != nil {
		if vault.IsFatalError(newCoreError) {
			c.UI.Error(fmt.Sprintf("Error initializing core: %s", newCoreError))
			return 1
		}
		c.UI.Warn(wrapAtLength(
			"WARNING! A non-fatal error occurred during initialization. Please " +
				"check the logs for more information."))
		c.UI.Warn("")

	}

	c.reloadFuncs = coreConfig.ReloadFuncs
	c.reloadFuncsLock = coreConfig.ReloadFuncsLock

	info["storage"] = config.Storage.Type
	info["mlock"] = fmt.Sprintf(
		"supported: %v, enabled: %v",
		mlock.Supported(), !config.DisableMlock && mlock.Supported())
	infoKeys = append(infoKeys, "mlock", "storage")

	if coreConfig.ClusterAddr != "" {
		info["cluster address"] = coreConfig.ClusterAddr
		infoKeys = append(infoKeys, "cluster address")
	}
	if coreConfig.RedirectAddr != "" {
		info["api address"] = coreConfig.RedirectAddr
		infoKeys = append(infoKeys, "api address")
	}

	if config.HAStorage != nil {
		info["HA storage"] = config.HAStorage.Type
		infoKeys = append(infoKeys, "HA storage")
	} else {
		// If the storage supports HA, then note it
		if coreConfig.HAPhysical != nil {
			if coreConfig.HAPhysical.HAEnabled() {
				info["storage"] += " (HA available)"
			} else {
				info["storage"] += " (HA disabled)"
			}
		}
	}

	status, lns, clusterAddrs, errMsg := c.InitListeners(config, disableClustering, &infoKeys, &info)
	if status != 0 {
		c.UI.Output("Error parsing listener configuration.")
		c.UI.Error(errMsg.Error())
		return 1
	}

	listenerCloseFunc := func() {
		for _, ln := range lns {
			ln.Listener.Close()
		}
	}

	defer c.cleanupGuard.Do(listenerCloseFunc)

	infoKeys = append(infoKeys, "version")
	verInfo := version.GetVersion()
	info["version"] = verInfo.FullVersionNumber(false)
	if verInfo.Revision != "" {
		info["version sha"] = strings.Trim(verInfo.Revision, "'")
		infoKeys = append(infoKeys, "version sha")
	}

	infoKeys = append(infoKeys, "cgo")
	info["cgo"] = "disabled"
	if version.CgoEnabled {
		info["cgo"] = "enabled"
	}

	infoKeys = append(infoKeys, "recovery mode")
	info["recovery mode"] = "false"

	infoKeys = append(infoKeys, "go version")
	info["go version"] = runtime.Version()

	fipsStatus := getFIPSInfoKey()
	if fipsStatus != "" {
		infoKeys = append(infoKeys, "fips")
		info["fips"] = fipsStatus
	}

	sort.Strings(infoKeys)
	c.UI.Output("==> Vault server configuration:\n")

	for _, k := range infoKeys {
		c.UI.Output(fmt.Sprintf(
			"%24s: %s",
			strings.Title(k),
			info[k]))
	}

	c.UI.Output("")

	if c.flagTestVerifyOnly {
		return 0
	}

	core.SetClusterListenerAddrs(clusterAddrs)
	core.SetClusterHandler(vaulthttp.Handler(&vault.HandlerProperties{
		Core: core,
	}))

	if !core.IsInSealMigrationMode() {
		panic("not implement")
	}

	wxc.P(core)
	// wxc.Print(metricSink, metricsHelper)
	return 0
}

// p2213
func (c *ServerCommand) detectRedirect(detect physical.RedirectDetect,
	config *server.Config,
) (string, error) {
	// Get the hostname
	host, err := detect.DetectHostAddr()
	if err != nil {
		return "", err
	}

	// set [] for ipv6 addresses
	if strings.Contains(host, ":") && !strings.Contains(host, "]") {
		host = "[" + host + "]"
	}

	// Default the port and scheme
	scheme := "https"
	port := 8200

	// Attempt to detect overrides
	for _, list := range config.Listeners {
		// Only attempt TCP
		if list.Type != "tcp" {
			continue
		}

		// Check if TLS is disabled
		if list.TLSDisable {
			scheme = "http"
		}

		// Check for address override
		addr := list.Address
		if addr == "" {
			addr = "127.0.0.1:8200"
		}

		// Check for localhost
		hostStr, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		if hostStr == "127.0.0.1" {
			host = hostStr
		}

		// Check for custom port
		listPort, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		port = listPort
	}

	// Build a URL
	url := &url.URL{
		Scheme: scheme,
		Host:   fmt.Sprintf("%s:%d", host, port),
	}

	// Return the URL string
	return url.String(), nil
}

// p2347
func (c *ServerCommand) storageMigrationActive(backend physical.Backend) bool {
	first := true

	for {
		migrationStatus, err := CheckStorageMigration(backend)
		if err == nil {
			if migrationStatus != nil {
				startTime := migrationStatus.Start.Format(time.RFC3339)
				c.UI.Error(wrapAtLength(fmt.Sprintf("ERROR! Storage migration in progress (started: %s). "+
					"Server startup is prevented until the migration completes. Use 'vault operator migrate -reset' "+
					"to force clear the migration lock.", startTime)))
				return true
			}
			return false
		}
		if first {
			first = false
			c.UI.Warn("\nWARNING! Unable to read storage migration status.")

			// unexpected state, so stop buffering log messages
			c.flushLog()
		}
		c.logger.Warn("storage migration check error", "error", err.Error())

		select {
		case <-time.After(2 * time.Second):
		case <-c.ShutdownCh:
			return true
		}
	}
}

type StorageMigrationStatus struct {
	Start time.Time `json:"start"`
}

func CheckStorageMigration(b physical.Backend) (*StorageMigrationStatus, error) {
	entry, err := b.Get(context.Background(), storageMigrationLock)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var status StorageMigrationStatus
	if err := jsonutil.DecodeJSON(entry.Value, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

// p2403
func setSeal(c *ServerCommand, config *server.Config, infoKeys []string, info map[string]string) (vault.Seal, wrapping.Wrapper, vault.Seal, []vault.Seal, error, error) {
	var barrierSeal vault.Seal
	var unwrapSeal vault.Seal

	var sealConfigError error
	var wrapper wrapping.Wrapper
	var barrierWrapper wrapping.Wrapper
	if c.flagDevAutoSeal {
		panic("not implement")
	}

	switch len(config.Seals) {
	case 0:
		config.Seals = append(config.Seals, &configutil.KMS{Type: wrapping.WrapperTypeShamir.String()})
	case 1:
		panic("not implement")
	}
	var createdSeals []vault.Seal = make([]vault.Seal, len(config.Seals))
	for _, configSeal := range config.Seals {
		sealType := wrapping.WrapperTypeShamir.String()
		if !configSeal.Disabled && os.Getenv("VAULT_SEAL_TYPE") != "" {
			sealType = os.Getenv("VAULT_SEAL_TYPE")
			configSeal.Type = sealType
		} else {
			sealType = configSeal.Type
		}

		var seal vault.Seal
		sealLogger := c.logger.ResetNamed(fmt.Sprintf("seal.%s", sealType))
		c.allLoggers = append(c.allLoggers, sealLogger)
		defaultSeal := vault.NewDefaultSeal(&vaultseal.Access{
			Wrapper: aeadwrapper.NewShamirWrapper(),
		})
		var sealInfoKeys []string
		sealInfoMap := map[string]string{}
		wrapper, sealConfigError = configutil.ConfigureWrapper(configSeal, &sealInfoKeys, &sealInfoMap, sealLogger)
		if sealConfigError != nil {
			if !errwrap.ContainsType(sealConfigError, new(logical.KeyNotFoundError)) {
				return barrierSeal, barrierWrapper, unwrapSeal, createdSeals, sealConfigError, fmt.Errorf(
					"Error parsing Seal configuration: %s", sealConfigError)
			}
		}
		if wrapper == nil {
			seal = defaultSeal
		} else {
			panic("not implement")
		}
		infoPrefix := ""
		if configSeal.Disabled {
			unwrapSeal = seal
			infoPrefix = "Old "
		} else {
			barrierSeal = seal
			barrierWrapper = wrapper
		}
		for _, k := range sealInfoKeys {
			infoKeys = append(infoKeys, infoPrefix+k)
			info[infoPrefix+k] = sealInfoMap[k]
		}
		createdSeals = append(createdSeals, seal)
	}
	return barrierSeal, barrierWrapper, unwrapSeal, createdSeals, sealConfigError, nil
}

// p2483
func initHaBackend(c *ServerCommand, config *server.Config, coreConfig *vault.CoreConfig, backend physical.Backend) (bool, error) {
	var ok bool
	if config.HAStorage != nil {
		panic("not implement")
	} else {
		if coreConfig.HAPhysical, ok = backend.(physical.HABackend); ok {
			panic("not implement")
		}
	}
	return config.DisableClustering, nil
}

// p2542
func determineRedirectAddr(c *ServerCommand, coreConfig *vault.CoreConfig, config *server.Config) error {
	var retErr error
	if envRA := os.Getenv("VAULT_API_ADDR"); envRA != "" {
		coreConfig.RedirectAddr = envRA
	} else if envRA := os.Getenv("VAULT_REDIRECT_ADDR"); envRA != "" {
		coreConfig.RedirectAddr = envRA
	} else if envAA := os.Getenv("VAULT_ADVERTISE_ADDR"); envAA != "" {
		coreConfig.RedirectAddr = envAA
	}

	// Attempt to detect the redirect address, if possible
	if coreConfig.RedirectAddr == "" {
		c.logger.Warn("no `api_addr` value specified in config or in VAULT_API_ADDR; falling back to detection if possible, but this value should be manually set")
	}

	var ok bool
	var detect physical.RedirectDetect
	if coreConfig.HAPhysical != nil && coreConfig.HAPhysical.HAEnabled() {
		detect, ok = coreConfig.HAPhysical.(physical.RedirectDetect)
	} else {
		detect, ok = coreConfig.Physical.(physical.RedirectDetect)
	}
	if ok && coreConfig.RedirectAddr == "" {
		redirect, err := c.detectRedirect(detect, config)
		// the following errors did not cause Run to return, so I'm not returning these
		// as errors.
		if err != nil {
			retErr = fmt.Errorf("Error detecting api address: %s", err)
		} else if redirect == "" {
			retErr = fmt.Errorf("Failed to detect api address")
		} else {
			coreConfig.RedirectAddr = redirect
		}
	}
	if coreConfig.RedirectAddr == "" && c.flagDev {
		protocol := "http"
		if c.flagDevTLS {
			protocol = "https"
		}
		coreConfig.RedirectAddr = fmt.Sprintf("%s://%s", protocol, config.Listeners[0].Address)
	}
	return retErr
}

// p2586
func findClusterAddress(c *ServerCommand, coreConfig *vault.CoreConfig, config *server.Config, disableClustering bool) error {
	if disableClustering {
		coreConfig.ClusterAddr = ""
	} else if envCA := os.Getenv("VAULT_CLUSTER_ADDR"); envCA != "" {
		coreConfig.ClusterAddr = envCA
	} else {
		var addrToUse string
		switch {
		case coreConfig.ClusterAddr == "" && coreConfig.RedirectAddr != "":
			addrToUse = coreConfig.RedirectAddr
		case c.flagDev:
			addrToUse = fmt.Sprintf("http://%s", config.Listeners[0].Address)
		default:
			goto CLUSTER_SYNTHESIS_COMPLETE
		}
		u, err := url.ParseRequestURI(addrToUse)
		if err != nil {
			return fmt.Errorf("Error parsing synthesized cluster address %s: %v", addrToUse, err)
		}
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			// This sucks, as it's a const in the function but not exported in the package
			if strings.Contains(err.Error(), "missing port in address") {
				host = u.Host
				port = "443"
			} else {
				return fmt.Errorf("Error parsing api address: %v", err)
			}
		}
		nPort, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("Error parsing synthesized address; failed to convert %q to a numeric: %v", port, err)
		}
		u.Host = net.JoinHostPort(host, strconv.Itoa(nPort+1))
		// Will always be TLS-secured
		u.Scheme = "https"
		coreConfig.ClusterAddr = u.String()
	}

CLUSTER_SYNTHESIS_COMPLETE:

	if coreConfig.RedirectAddr == coreConfig.ClusterAddr && len(coreConfig.RedirectAddr) != 0 {
		return fmt.Errorf("Address %q used for both API and cluster addresses", coreConfig.RedirectAddr)
	}

	if coreConfig.ClusterAddr != "" {
		rendered, err := configutil.ParseSingleIPTemplate(coreConfig.ClusterAddr)
		if err != nil {
			return fmt.Errorf("Error parsing cluster address %s: %v", coreConfig.ClusterAddr, err)
		}
		coreConfig.ClusterAddr = rendered
		// Force https as we'll always be TLS-secured
		u, err := url.ParseRequestURI(coreConfig.ClusterAddr)
		if err != nil {
			return fmt.Errorf("Error parsing cluster address %s: %v", coreConfig.ClusterAddr, err)
		}
		u.Scheme = "https"
		coreConfig.ClusterAddr = u.String()
	}
	return nil
}

// p2669
func createCoreConfig(c *ServerCommand, config *server.Config, backend physical.Backend, configSR sr.ServiceRegistration, barrierSeal, unwrapSeal vault.Seal,
	metricsHelper *metricsutil.MetricsHelper, metricSink *metricsutil.ClusterMetricSink, secureRandomReader io.Reader,
) vault.CoreConfig {
	coreConfig := &vault.CoreConfig{
		RawConfig:                      config,
		Physical:                       backend,
		RedirectAddr:                   config.Storage.RedirectAddr,
		StorageType:                    config.Storage.Type,
		HAPhysical:                     nil,
		ServiceRegistration:            configSR,
		Seal:                           barrierSeal,
		UnwrapSeal:                     unwrapSeal,
		AuditBackends:                  c.AuditBackends,
		CredentialBackends:             c.CredentialBackends,
		LogicalBackends:                c.LogicalBackends,
		Logger:                         c.logger,
		DisableSentinelTrace:           config.DisableSentinelTrace,
		DisableCache:                   config.DisableCache,
		DisableMlock:                   config.DisableMlock,
		MaxLeaseTTL:                    config.MaxLeaseTTL,
		DefaultLeaseTTL:                config.DefaultLeaseTTL,
		ClusterName:                    config.ClusterName,
		CacheSize:                      config.CacheSize,
		PluginDirectory:                config.PluginDirectory,
		PluginFileUid:                  config.PluginFileUid,
		PluginFilePermissions:          config.PluginFilePermissions,
		EnableUI:                       config.EnableUI,
		EnableRaw:                      config.EnableRawEndpoint,
		DisableSealWrap:                config.DisableSealWrap,
		DisablePerformanceStandby:      config.DisablePerformanceStandby,
		DisableIndexing:                config.DisableIndexing,
		AllLoggers:                     c.allLoggers,
		BuiltinRegistry:                builtinplugins.Registry,
		DisableKeyEncodingChecks:       config.DisablePrintableCheck,
		MetricsHelper:                  metricsHelper,
		MetricSink:                     metricSink,
		SecureRandomReader:             secureRandomReader,
		EnableResponseHeaderHostname:   config.EnableResponseHeaderHostname,
		EnableResponseHeaderRaftNodeID: config.EnableResponseHeaderRaftNodeID,
		License:                        config.License,
		LicensePath:                    config.LicensePath,
		DisableSSCTokens:               config.DisableSSCTokens,
	}

	if c.flagDev {
		coreConfig.EnableRaw = true
		coreConfig.DevToken = c.flagDevRootTokenID
		if c.flagDevLeasedKV {
			coreConfig.LogicalBackends["kv"] = vault.LeasedPassthroughBackendFactory
		}
		if c.flagDevPluginDir != "" {
			coreConfig.PluginDirectory = c.flagDevPluginDir
		}
		if c.flagDevLatency > 0 {
			injectLatency := time.Duration(c.flagDevLatency) * time.Millisecond
			if _, txnOK := backend.(physical.Transactional); txnOK {
				coreConfig.Physical = physical.NewTransactionalLatencyInjector(backend, injectLatency, c.flagDevLatencyJitter, c.logger)
			} else {
				coreConfig.Physical = physical.NewLatencyInjector(backend, injectLatency, c.flagDevLatencyJitter, c.logger)
			}
		}
	}
	return *coreConfig
}

// p2952
type grpclogFaker struct {
	logger hclog.Logger
	log    bool
}

func (g *grpclogFaker) Fatal(args ...interface{}) {
	g.logger.Error(fmt.Sprint(args...))
	os.Exit(1)
}

func (g *grpclogFaker) Fatalf(format string, args ...interface{}) {
	g.logger.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

func (g *grpclogFaker) Fatalln(args ...interface{}) {
	g.logger.Error(fmt.Sprintln(args...))
	os.Exit(1)
}

func (g *grpclogFaker) Print(args ...interface{}) {
	if g.log && g.logger.IsDebug() {
		g.logger.Debug(fmt.Sprint(args...))
	}
}

func (g *grpclogFaker) Printf(format string, args ...interface{}) {
	if g.log && g.logger.IsDebug() {
		g.logger.Debug(fmt.Sprintf(format, args...))
	}
}

func (g *grpclogFaker) Println(args ...interface{}) {
	if g.log && g.logger.IsDebug() {
		g.logger.Debug(fmt.Sprintln(args...))
	}
}
