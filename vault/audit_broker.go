package vault

import (
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/audit"
)

type backendEntry struct {
	backend audit.Backend
	view    *BarrierView
	local   bool
}

// p24
type AuditBroker struct {
	sync.RWMutex
	backends map[string]backendEntry
	logger   log.Logger
}
