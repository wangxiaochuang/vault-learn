package vault

import (
	"context"
	"sync"
	"time"

	log "github.com/hashicorp/go-hclog"
)

// p28
type RollbackManager struct {
	logger log.Logger

	// This gives the current mount table of both logical and credential backends,
	// plus a RWMutex that is locked for reading. It is up to the caller to RUnlock
	// it when done with the mount table.
	backends func() []*MountEntry

	router *Router
	period time.Duration

	inflightAll  sync.WaitGroup
	inflight     map[string]*rollbackState
	inflightLock sync.RWMutex

	doneCh       chan struct{}
	shutdown     bool
	shutdownCh   chan struct{}
	shutdownLock sync.Mutex
	quitContext  context.Context

	core *Core
}

type rollbackState struct {
	lastError error
	sync.WaitGroup
	cancelLockGrabCtx       context.Context
	cancelLockGrabCtxCancel context.CancelFunc
}
