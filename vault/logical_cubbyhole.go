package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/versions"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

func CubbyholeBackendFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &CubbyholeBackend{}
	b.Backend = &framework.Backend{
		Help:           strings.TrimSpace(cubbyholeHelp),
		RunningVersion: versions.GetBuiltinVersion(consts.PluginTypeSecrets, "cubbyhole"),
	}

	b.Backend.Paths = append(b.Backend.Paths, b.paths()...)

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}
	b.Backend.Setup(ctx, conf)

	return b, nil
}

// p38
type CubbyholeBackend struct {
	*framework.Backend

	saltUUID    string
	storageView logical.Storage
}

func (b *CubbyholeBackend) paths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: framework.MatchAllRegex("path"),

			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "Specifies the path of the secret.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRead,
					Summary:  "Retrieve the secret at the specified location.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
					Summary:  "Store a secret at the specified location.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleDelete,
					Summary:  "Deletes the secret at the specified location.",
				},
				logical.ListOperation: &framework.PathOperation{
					Callback:    b.handleList,
					Summary:     "List secret entries at the specified location.",
					Description: "Folders are suffixed with /. The input must be a folder; list on a file will not return a value. The values themselves are not accessible via this command.",
				},
			},

			ExistenceCheck: b.handleExistenceCheck,

			HelpSynopsis:    strings.TrimSpace(cubbyholeHelpSynopsis),
			HelpDescription: strings.TrimSpace(cubbyholeHelpDescription),
		},
	}
}

func (b *CubbyholeBackend) revoke(ctx context.Context, view *BarrierView, saltedToken string) error {
	panic("not implement")
}

func (b *CubbyholeBackend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	panic("not implement")
}

func (b *CubbyholeBackend) handleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("not implement")
}

func (b *CubbyholeBackend) handleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("not implement")
}

func (b *CubbyholeBackend) handleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("not implement")
}

func (b *CubbyholeBackend) handleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("not implement")
}

// p225
const cubbyholeHelp = `
The cubbyhole backend reads and writes arbitrary secrets to the backend.
The secrets are encrypted/decrypted by Vault: they are never stored
unencrypted in the backend and the backend never has an opportunity to
see the unencrypted value.

This backend differs from the 'kv' backend in that it is namespaced
per-token. Tokens can only read and write their own values, with no
sharing possible (per-token cubbyholes). This can be useful for implementing
certain authentication workflows, as well as "scratch" areas for individual
clients. When the token is revoked, the entire set of stored values for that
token is also removed.
`

const cubbyholeHelpSynopsis = `
Pass-through secret storage to a token-specific cubbyhole in the storage
backend, allowing you to read/write arbitrary data into secret storage.
`

const cubbyholeHelpDescription = `
The cubbyhole backend reads and writes arbitrary data into secret storage,
encrypting it along the way.

The view into the cubbyhole storage space is different for each token; it is
a per-token cubbyhole. When the token is revoked all values are removed.
`
