package vault

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

func LeasedPassthroughBackendFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	return LeaseSwitchedPassthroughBackend(ctx, conf, true)
}

func LeaseSwitchedPassthroughBackend(ctx context.Context, conf *logical.BackendConfig, leases bool) (logical.Backend, error) {
	panic("not implement")
}
