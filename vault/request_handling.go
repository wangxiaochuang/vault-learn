package vault

import (
	"time"
)

const (
	replTimeout                           = 1 * time.Second
	EnvVaultDisableLocalAuthMountEntities = "VAULT_DISABLE_LOCAL_AUTH_MOUNT_ENTITIES"
)

var (
	DefaultMaxRequestDuration     = 90 * time.Second
	egpDebugLogging               bool
	enterpriseBlockRequestIfError = blockRequestIfErrorImpl
)
