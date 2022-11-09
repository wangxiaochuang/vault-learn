package vault

import (
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-memdb"
	"github.com/hashicorp/vault/sdk/framework"
)

// p72
type PolicyMFABackend struct {
	*MFABackend
}

// p229
type SystemBackend struct {
	*framework.Backend
	Core       *Core
	db         *memdb.MemDB
	logger     log.Logger
	mfaBackend *PolicyMFABackend
}
