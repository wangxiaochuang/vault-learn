package vault

import (
	"context"
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/identity"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/sdk/logical"
)

// p703
type TokenStore struct {
	*framework.Backend

	activeContext context.Context

	core *Core

	batchTokenEncryptor BarrierEncryptor

	baseBarrierView     *BarrierView
	idBarrierView       *BarrierView
	accessorBarrierView *BarrierView
	parentBarrierView   *BarrierView
	rolesBarrierView    *BarrierView

	expiration *ExpirationManager

	cubbyholeBackend *CubbyholeBackend

	tokenLocks []*locksutil.LockEntry

	tokensPendingDeletion *sync.Map

	cubbyholeDestroyer func(context.Context, *TokenStore, *logical.TokenEntry) error

	logger log.Logger

	saltLock sync.RWMutex
	salts    map[string]*salt.Salt

	tidyLock *uint32

	identityPoliciesDeriverFunc func(string) (*identity.Entity, []string, error)

	quitContext context.Context

	sscTokensGenerationCounter SSCTokenGenerationCounter
}
