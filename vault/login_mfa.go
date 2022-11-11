package vault

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-memdb"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/patrickmn/go-cache"
)

const (
	mfaMethodTypeTOTP              = "totp"
	mfaMethodTypeDuo               = "duo"
	mfaMethodTypeOkta              = "okta"
	mfaMethodTypePingID            = "pingid"
	memDBLoginMFAConfigsTable      = "login_mfa_configs"
	memDBMFALoginEnforcementsTable = "login_enforcements"
	mfaTOTPKeysPrefix              = systemBarrierPrefix + "mfa/totpkeys/"

	// loginMFAConfigPrefix is the storage prefix for persisting login MFA method
	// configs
	loginMFAConfigPrefix      = "login-mfa/method/"
	mfaLoginEnforcementPrefix = "login-mfa/enforcement/"
)

type totpKey struct {
	Key string `json:"key"`
}

func (b *SystemBackend) loginMFAPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "mfa/validate",
			Fields: map[string]*framework.FieldSchema{
				"mfa_request_id": {
					Type:        framework.TypeString,
					Description: "ID for this MFA request",
					Required:    true,
				},
				"mfa_payload": {
					Type:        framework.TypeMap,
					Description: "A map from MFA method ID to a slice of passcodes or an empty slice if the method does not use passcodes",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                  b.Core.loginMFABackend.handleMFALoginValidate,
					Summary:                   "Validates the login for the given MFA methods. Upon successful validation, it returns an auth response containing the client token",
					ForwardPerformanceStandby: true,
				},
			},
		},
	}
}

func genericOptionalUUIDRegex(name string) string {
	return fmt.Sprintf("(/(?P<%s>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))?", name)
}

// p99
type MFABackend struct {
	Core        *Core
	mfaLock     *sync.RWMutex
	db          *memdb.MemDB
	mfaLogger   hclog.Logger
	namespacer  Namespacer
	methodTable string
	usedCodes   *cache.Cache
}

// 109
type LoginMFABackend struct {
	*MFABackend
}

func loginMFASchemaFuncs() []func() *memdb.TableSchema {
	return []func() *memdb.TableSchema{
		loginMFAConfigTableSchema,
		loginEnforcementTableSchema,
	}
}

// p120
func NewLoginMFABackend(core *Core, logger hclog.Logger) *LoginMFABackend {
	b := NewMFABackend(core, logger, memDBLoginMFAConfigsTable, loginMFASchemaFuncs())
	return &LoginMFABackend{b}
}

func NewMFABackend(core *Core, logger hclog.Logger, prefix string, schemaFuncs []func() *memdb.TableSchema) *MFABackend {
	db, _ := SetupMFAMemDB(schemaFuncs)
	return &MFABackend{
		Core:        core,
		mfaLock:     &sync.RWMutex{},
		db:          db,
		mfaLogger:   logger.Named("mfa"),
		namespacer:  core,
		methodTable: prefix,
	}
}

func SetupMFAMemDB(schemaFuncs []func() *memdb.TableSchema) (*memdb.MemDB, error) {
	mfaSchemas := &memdb.DBSchema{
		Tables: make(map[string]*memdb.TableSchema),
	}

	for _, schemaFunc := range schemaFuncs {
		schema := schemaFunc()
		if _, ok := mfaSchemas.Tables[schema.Name]; ok {
			panic(fmt.Sprintf("duplicate table name: %s", schema.Name))
		}
		mfaSchemas.Tables[schema.Name] = schema
	}

	db, err := memdb.NewMemDB(mfaSchemas)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// p650
func (b *LoginMFABackend) handleMFALoginValidate(ctx context.Context, req *logical.Request, d *framework.FieldData) (retResp *logical.Response, retErr error) {
	panic("not implement")
}

// p2318
func loginMFAConfigTableSchema() *memdb.TableSchema {
	return &memdb.TableSchema{
		Name: memDBLoginMFAConfigsTable,
		Indexes: map[string]*memdb.IndexSchema{
			"id": {
				Name:   "id",
				Unique: true,
				Indexer: &memdb.StringFieldIndex{
					Field: "ID",
				},
			},
			"namespace_id": {
				Name:   "namespace_id",
				Unique: false,
				Indexer: &memdb.StringFieldIndex{
					Field: "NamespaceID",
				},
			},
			"type": {
				Name:   "type",
				Unique: false,
				Indexer: &memdb.StringFieldIndex{
					Field: "Type",
				},
			},
		},
	}
}

func loginEnforcementTableSchema() *memdb.TableSchema {
	return &memdb.TableSchema{
		Name: memDBMFALoginEnforcementsTable,
		Indexes: map[string]*memdb.IndexSchema{
			"id": {
				Name:   "id",
				Unique: true,
				Indexer: &memdb.StringFieldIndex{
					Field: "ID",
				},
			},
			"namespace": {
				Name:   "namespace",
				Unique: false,
				Indexer: &memdb.StringFieldIndex{
					Field: "NamespaceID",
				},
			},
			"nameAndNamespace": {
				Name:   "nameAndNamespace",
				Unique: true,
				Indexer: &memdb.CompoundIndex{
					Indexes: []memdb.Indexer{
						&memdb.StringFieldIndex{
							Field: "Name",
						},
						&memdb.StringFieldIndex{
							Field: "NamespaceID",
						},
					},
				},
			},
		},
	}
}
