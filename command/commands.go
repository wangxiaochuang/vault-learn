package command

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
	sr "github.com/hashicorp/vault/serviceregistration"
	"github.com/mitchellh/cli"
)

const (
	EnvVaultCLINoColor                = `VAULT_CLI_NO_COLOR`
	EnvVaultFormat                    = `VAULT_FORMAT`
	EnvVaultLicense                   = "VAULT_LICENSE"
	EnvVaultLicensePath               = "VAULT_LICENSE_PATH"
	EnvVaultDetailed                  = `VAULT_DETAILED`
	DisableSSCTokens                  = "VAULT_DISABLE_SERVER_SIDE_CONSISTENT_TOKENS"
	flagNameAddress                   = "address"
	flagNameCACert                    = "ca-cert"
	flagNameCAPath                    = "ca-path"
	flagNameClientKey                 = "client-key"
	flagNameClientCert                = "client-cert"
	flagNameTLSSkipVerify             = "tls-skip-verify"
	flagTLSServerName                 = "tls-server-name"
	flagNameAuditNonHMACRequestKeys   = "audit-non-hmac-request-keys"
	flagNameAuditNonHMACResponseKeys  = "audit-non-hmac-response-keys"
	flagNameDescription               = "description"
	flagNameListingVisibility         = "listing-visibility"
	flagNamePassthroughRequestHeaders = "passthrough-request-headers"
	flagNameAllowedResponseHeaders    = "allowed-response-headers"
	flagNameTokenType                 = "token-type"
	flagNameAllowedManagedKeys        = "allowed-managed-keys"
	flagNamePluginVersion             = "plugin-version"
	flagNameDisableRedirects          = "disable-redirects"
)

var (
	auditBackends = map[string]audit.Factory{
		// "file": auditFile.Factory,
	}
	credentialBackends = map[string]logical.Factory{
		// "plugin": plugin.Factory,
	}

	logicalBackends = map[string]logical.Factory{
		// "plugin": plugin.Factory,
		// "kv":     logicalKv.Factory,
	}

	physicalBackends = map[string]physical.Factory{
		// "file": physFile.NewFileBackend,
	}

	serviceRegistrations = map[string]sr.Factory{
		// "consul": csr.NewServiceRegistration,
	}

	initCommandsEnt = func(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {}
)

// p192
var Commands map[string]cli.CommandFactory

func initCommands(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
	Commands = map[string]cli.CommandFactory{
		"server": func() (cli.Command, error) {
			return &ServerCommand{
				BaseCommand: &BaseCommand{
					UI:          serverCmdUi,
					tokenHelper: runOpts.TokenHelper,
					flagAddress: runOpts.Address,
				},
				AuditBackends:      auditBackends,
				CredentialBackends: credentialBackends,
				LogicalBackends:    logicalBackends,
				PhysicalBackends:   physicalBackends,

				ServiceRegistrations: serviceRegistrations,

				ShutdownCh: MakeShutdownCh(),
				SighupCh:   MakeSighupCh(),
				SigUSR2Ch:  MakeSigUSR2Ch(),
			}, nil
		},
	}
	// if os.Getenv(OperatorDiagnoseEnableEnv) != "" {
	// 	panic("not implement")
	// }
	initCommandsEnt(ui, serverCmdUi, runOpts)
}

func MakeShutdownCh() chan struct{} {
	resultCh := make(chan struct{})

	shutdownCh := make(chan os.Signal, 4)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdownCh
		close(resultCh)
	}()
	return resultCh
}

func MakeSighupCh() chan struct{} {
	resultCh := make(chan struct{})

	signalCh := make(chan os.Signal, 4)
	signal.Notify(signalCh, syscall.SIGHUP)
	go func() {
		for {
			<-signalCh
			resultCh <- struct{}{}
		}
	}()
	return resultCh
}
