package vault

import (
	"time"

	"github.com/hashicorp/vault/internalshared/configutil"
	uberAtomic "go.uber.org/atomic"
)

const (
	replTimeout                           = 1 * time.Second
	EnvVaultDisableLocalAuthMountEntities = "VAULT_DISABLE_LOCAL_AUTH_MOUNT_ENTITIES"
)

var (
	DefaultMaxRequestDuration = 90 * time.Second
	egpDebugLogging           bool
)

// p56
type HandlerProperties struct {
	Core                  *Core
	ListenerConfig        *configutil.Listener
	DisablePrintableCheck bool
	RecoveryMode          bool
	RecoveryToken         *uberAtomic.String
}
