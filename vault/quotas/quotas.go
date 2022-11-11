package quotas

import (
	"context"
	"errors"
	"sync"

	log "github.com/hashicorp/go-hclog"

	"github.com/hashicorp/go-memdb"
	"github.com/hashicorp/vault/helper/metricsutil"
	"github.com/hashicorp/vault/sdk/helper/pathmanager"
	"github.com/hashicorp/vault/sdk/logical"
)

// p20
type Type string

const (
	// TypeRateLimit represents the rate limiting quota type
	TypeRateLimit Type = "rate-limit"

	// TypeLeaseCount represents the lease count limiting quota type
	TypeLeaseCount Type = "lease-count"
)

type LeaseAction uint32

// String converts each lease action into its string equivalent value
func (la LeaseAction) String() string {
	switch la {
	case LeaseActionLoaded:
		return "loaded"
	case LeaseActionCreated:
		return "created"
	case LeaseActionDeleted:
		return "deleted"
	case LeaseActionAllow:
		return "allow"
	}
	return "unknown"
}

const (
	_ LeaseAction = iota

	LeaseActionLoaded

	LeaseActionCreated

	LeaseActionDeleted

	LeaseActionAllow
)

type leaseWalkFunc func(context.Context, func(request *Request) bool) error

// String converts each quota type into its string equivalent value
func (q Type) String() string {
	switch q {
	case TypeLeaseCount:
		return "lease-count"
	case TypeRateLimit:
		return "rate-limit"
	}
	return "unknown"
}

const (
	indexID                 = "id"
	indexName               = "name"
	indexNamespace          = "ns"
	indexNamespaceMount     = "ns_mount"
	indexNamespaceMountPath = "ns_mount_path"
	indexNamespaceMountRole = "ns_mount_role"
)

const (
	StoragePrefix = "quotas/"

	ConfigPath = StoragePrefix + "config"

	DefaultRateLimitExemptPathsToggle = StoragePrefix + "default_rate_limit_exempt_paths_toggle"
)

var (
	ErrLeaseCountQuotaExceeded = errors.New("lease count quota exceeded")

	ErrRateLimitQuotaExceeded = errors.New("rate limit quota exceeded")
)

var defaultExemptPaths = []string{
	"/v1/sys/generate-recovery-token/attempt",
	"/v1/sys/generate-recovery-token/update",
	"/v1/sys/generate-root/attempt",
	"/v1/sys/generate-root/update",
	"/v1/sys/health",
	"/v1/sys/seal-status",
	"/v1/sys/unseal",
}

type Access interface {
	QuotaID() string
}

var _ Access = (*access)(nil)

type access struct {
	quotaID string
}

func (a *access) QuotaID() string {
	return a.quotaID
}

// p151
type Manager struct {
	entManager

	// db holds the in memory instances of all active quota rules indexed by
	// some of the quota properties.
	db *memdb.MemDB

	// config containing operator preferences and quota behaviors
	config *Config

	rateLimitPathManager *pathmanager.PathManager

	storage logical.Storage
	ctx     context.Context

	logger     log.Logger
	metricSink *metricsutil.ClusterMetricSink
	lock       *sync.RWMutex
}

// p173
type QuotaLeaseInformation struct {
	LeaseId string
	Role    string
}

// p183
type Quota interface {
	allow(context.Context, *Request) (Response, error)

	quotaID() string

	QuotaName() string

	initialize(log.Logger, *metricsutil.ClusterMetricSink) error

	close(context.Context) error

	Clone() Quota

	handleRemount(string, string)
}

// p210
type Response struct {
	Allowed bool

	Access Access

	Headers map[string]string
}

type Config struct {
	EnableRateLimitAuditLogging bool `json:"enable_rate_limit_audit_logging"`

	EnableRateLimitResponseHeaders bool `json:"enable_rate_limit_response_headers"`

	RateLimitExemptPaths []string `json:"rate_limit_exempt_paths"`
}

// p241
type Request struct {
	// Type is the quota type
	Type Type

	Path string

	Role string

	NamespacePath string

	MountPath string

	ClientAddress string
}

// p264
func NewManager(logger log.Logger, walkFunc leaseWalkFunc, ms *metricsutil.ClusterMetricSink) (*Manager, error) {
	db, err := memdb.NewMemDB(dbSchema())
	if err != nil {
		return nil, err
	}

	manager := &Manager{
		db:                   db,
		logger:               logger,
		metricSink:           ms,
		rateLimitPathManager: pathmanager.New(),
		config:               new(Config),
		lock:                 new(sync.RWMutex),
	}

	manager.init(walkFunc)

	return manager, nil
}

// p785
func dbSchema() *memdb.DBSchema {
	schema := &memdb.DBSchema{
		Tables: make(map[string]*memdb.TableSchema),
	}

	commonSchema := func(name string) *memdb.TableSchema {
		return &memdb.TableSchema{
			Name: name,
			Indexes: map[string]*memdb.IndexSchema{
				indexID: {
					Name:   indexID,
					Unique: true,
					Indexer: &memdb.StringFieldIndex{
						Field: "ID",
					},
				},
				indexName: {
					Name:   indexName,
					Unique: true,
					Indexer: &memdb.StringFieldIndex{
						Field: "Name",
					},
				},
				indexNamespace: {
					Name: indexNamespace,
					Indexer: &memdb.CompoundMultiIndex{
						Indexes: []memdb.Indexer{
							&memdb.StringFieldIndex{
								Field: "NamespacePath",
							},
							// By sending false as the query parameter, we can
							// query just the namespace specific quota.
							&memdb.FieldSetIndex{
								Field: "MountPath",
							},
							// By sending false as the query parameter, we can
							// query just the namespace specific quota.
							&memdb.FieldSetIndex{
								Field: "PathSuffix",
							},
							// By sending false as the query parameter, we can
							// query just the namespace specific quota.
							&memdb.FieldSetIndex{
								Field: "Role",
							},
						},
					},
				},
				indexNamespaceMount: {
					Name:         indexNamespaceMount,
					AllowMissing: true,
					Indexer: &memdb.CompoundMultiIndex{
						Indexes: []memdb.Indexer{
							&memdb.StringFieldIndex{
								Field: "NamespacePath",
							},
							&memdb.StringFieldIndex{
								Field: "MountPath",
							},
							// By sending false as the query parameter, we can
							// query just the namespace specific quota.
							&memdb.FieldSetIndex{
								Field: "PathSuffix",
							},
							// By sending false as the query parameter, we can
							// query just the namespace specific quota.
							&memdb.FieldSetIndex{
								Field: "Role",
							},
						},
					},
				},
				indexNamespaceMountRole: {
					Name:         indexNamespaceMountRole,
					AllowMissing: true,
					Indexer: &memdb.CompoundMultiIndex{
						Indexes: []memdb.Indexer{
							&memdb.StringFieldIndex{
								Field: "NamespacePath",
							},
							&memdb.StringFieldIndex{
								Field: "MountPath",
							},
							// By sending false as the query parameter, we can
							// query just the role specific quota.
							&memdb.FieldSetIndex{
								Field: "PathSuffix",
							},
							&memdb.StringFieldIndex{
								Field: "Role",
							},
						},
					},
				},
				indexNamespaceMountPath: {
					Name:         indexNamespaceMountPath,
					AllowMissing: true,
					Indexer: &memdb.CompoundMultiIndex{
						Indexes: []memdb.Indexer{
							&memdb.StringFieldIndex{
								Field: "NamespacePath",
							},
							&memdb.StringFieldIndex{
								Field: "MountPath",
							},
							&memdb.StringFieldIndex{
								Field: "PathSuffix",
							},
							// By sending false as the query parameter, we can
							// query just the namespace specific quota.
							&memdb.FieldSetIndex{
								Field: "Role",
							},
						},
					},
				},
			},
		}
	}

	for _, name := range quotaTypes() {
		schema.Tables[name] = commonSchema(name)
	}

	return schema
}
