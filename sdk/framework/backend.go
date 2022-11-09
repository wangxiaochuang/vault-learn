package framework

import (
	"context"
	"log"
	"regexp"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// p36
type Backend struct {
	Help string

	Paths        []*Path
	PathsSpecial *logical.Paths

	Secrets []*Secret

	InitializeFunc InitializeFunc

	PeriodicFunc periodicFunc

	WALRollback       WALRollbackFunc
	WALRollbackMinAge time.Duration

	Clean CleanupFunc

	Invalidate InvalidateFunc

	AuthRenew OperationFunc

	BackendType logical.BackendType

	RunningVersion string

	logger  log.Logger
	system  logical.SystemView
	once    sync.Once
	pathsRe []*regexp.Regexp
}

// p106
type periodicFunc func(context.Context, *logical.Request) error

type OperationFunc func(context.Context, *logical.Request, *FieldData) (*logical.Response, error)

type ExistenceFunc func(context.Context, *logical.Request, *FieldData) (bool, error)

type WALRollbackFunc func(context.Context, *logical.Request, string, interface{}) error

type CleanupFunc func(context.Context)

type InvalidateFunc func(context.Context, string)

type InitializeFunc func(context.Context, *logical.InitializationRequest) error

type PatchPreprocessorFunc func(map[string]interface{}) (map[string]interface{}, error)

// p684
type FieldSchema struct {
	Type        FieldType
	Default     interface{}
	Description string

	Required   bool
	Deprecated bool

	Query bool

	AllowedValues []interface{}

	DisplayAttrs *DisplayAttributes
}
