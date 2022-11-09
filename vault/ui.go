package vault

import (
	"net/http"
	"sync"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
)

// p23
type UIConfig struct {
	l               sync.RWMutex
	physicalStorage physical.Backend
	barrierStorage  logical.Storage

	enabled        bool
	defaultHeaders http.Header
}
