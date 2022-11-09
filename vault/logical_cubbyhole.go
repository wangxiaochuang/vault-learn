package vault

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// p38
type CubbyholeBackend struct {
	*framework.Backend

	saltUUID    string
	storageView logical.Storage
}
