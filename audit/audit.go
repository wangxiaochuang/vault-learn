package audit

import (
	"context"

	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/sdk/logical"
)

type Backend interface {
	LogRequest(context.Context, *logical.LogInput) error
	LogResponse(context.Context, *logical.LogInput) error
	LogTestMessage(context.Context, *logical.LogInput, map[string]string) error
	GetHash(context.Context, string) (string, error)
	Reload(context.Context) error
	Invalidate(context.Context)
}

type BackendConfig struct {
	SaltView   logical.Storage
	SaltConfig *salt.Config
	Config     map[string]string
}

type Factory func(context.Context, *BackendConfig) (Backend, error)
