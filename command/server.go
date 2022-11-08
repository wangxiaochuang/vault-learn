package command

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/gatedwriter"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/command/server"
	"github.com/hashicorp/vault/helper/constants"
	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
	sr "github.com/hashicorp/vault/serviceregistration"
	"github.com/hashicorp/vault/vault"
	"github.com/hashicorp/vault/wxc"
	"github.com/posener/complete"
	"google.golang.org/grpc/grpclog"
)

var memProfilerEnabled = false

var enableFourClusterDev = func(c *ServerCommand, base *vault.CoreConfig, info map[string]string, infoKeys []string, devListenAddress, tempDir string) int {
	c.logger.Error("-dev-four-cluster only supported in enterprise Vault")
	return 1
}

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

	wxc.Print(logLevelStr)
	wxc.Print(logLevelString)
	return 0
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
