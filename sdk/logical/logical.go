package logical

import (
	"context"

	log "github.com/hashicorp/go-hclog"
)

type BackendType uint32

const (
	TypeUnknown    BackendType = 0
	TypeLogical    BackendType = 1
	TypeCredential BackendType = 2
)

func (b BackendType) String() string {
	switch b {
	case TypeLogical:
		return "secret"
	case TypeCredential:
		return "auth"
	}

	return "unknown"
}

type Backend interface {
	Initialize(context.Context, *InitializationRequest) error
	HandleRequest(context.Context, *Request) (*Response, error)
	SpecialPaths() *Paths
	System() SystemView
	Logger() log.Logger
	HandleExistenceCheck(context.Context, *Request) (bool, bool, error)
	Cleanup(context.Context)
	InvalidateKey(context.Context, string)
	Setup(context.Context, *BackendConfig) error
	Type() BackendType
}

type BackendConfig struct {
}

// p111
type Factory func(context.Context, *BackendConfig) (Backend, error)

type Paths struct {
	Root            []string
	Unauthenticated []string
	LocalStorage    []string
	SealWrapStorage []string
}
