package vault

import (
	"context"
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-memdb"
	"github.com/hashicorp/vault/helper/identity"
	"github.com/hashicorp/vault/helper/metricsutil"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/helper/storagepacker"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

// p44
type IdentityStore struct {
	*framework.Backend

	view logical.Storage

	db *memdb.MemDB

	lock     sync.RWMutex
	oidcLock sync.RWMutex

	groupLock sync.RWMutex

	oidcCache *oidcCache

	oidcAuthCodeCache *oidcCache

	logger log.Logger

	entityPacker *storagepacker.StoragePacker

	localAliasPacker *storagepacker.StoragePacker

	groupPacker *storagepacker.StoragePacker

	disableLowerCasedNames bool

	router        *Router
	redirectAddr  string
	localNode     LocalNode
	namespacer    Namespacer
	metrics       metricsutil.Metrics
	totpPersister TOTPPersister
	groupUpdater  GroupUpdater
	tokenStorer   TokenStorer
	entityCreator EntityCreator
	mfaBackend    *LoginMFABackend
}

// p115
type LocalNode interface {
	ReplicationState() consts.ReplicationState
	HAState() consts.HAState
}

// p122
type Namespacer interface {
	NamespaceByID(context.Context, string) (*namespace.Namespace, error)
	ListNamespaces(includePath bool) []*namespace.Namespace
}

// p129
type TOTPPersister interface {
	PersistTOTPKey(ctx context.Context, configID string, entityID string, key string) error
}

// p135
type GroupUpdater interface {
	SendGroupUpdate(ctx context.Context, group *identity.Group) (bool, error)
}

// p141
type TokenStorer interface {
	LookupToken(context.Context, string) (*logical.TokenEntry, error)
	CreateToken(context.Context, *logical.TokenEntry) error
}

// p148
type EntityCreator interface {
	CreateEntity(ctx context.Context) (*identity.Entity, error)
}
