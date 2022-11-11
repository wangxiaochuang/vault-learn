package namespace

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type contextValues struct{}

type Namespace struct {
	ID             string            `json:"id" mapstructure:"id"`
	Path           string            `json:"path" mapstructure:"path"`
	CustomMetadata map[string]string `json:"custom_metadata" mapstructure:"custom_metadata"`
}

func (n *Namespace) String() string {
	return fmt.Sprintf("ID: %s. Path: %s", n.ID, n.Path)
}

const (
	RootNamespaceID = "root"
)

var (
	contextNamespace contextValues = struct{}{}
	ErrNoNamespace   error         = errors.New("no namespace")
	RootNamespace    *Namespace    = &Namespace{
		ID:             RootNamespaceID,
		Path:           "",
		CustomMetadata: make(map[string]string),
	}
)

func (n *Namespace) HasParent(possibleParent *Namespace) bool {
	switch {
	case possibleParent.Path == "":
		return true
	case n.Path == "":
		return false
	default:
		return strings.HasPrefix(n.Path, possibleParent.Path)
	}
}

func (n *Namespace) TrimmedPath(path string) string {
	return strings.TrimPrefix(path, n.Path)
}

func ContextWithNamespace(ctx context.Context, ns *Namespace) context.Context {
	return context.WithValue(ctx, contextNamespace, ns)
}

func RootContext(ctx context.Context) context.Context {
	if ctx == nil {
		return ContextWithNamespace(context.Background(), RootNamespace)
	}
	return ContextWithNamespace(ctx, RootNamespace)
}

// p69
func FromContext(ctx context.Context) (*Namespace, error) {
	if ctx == nil {
		return nil, errors.New("context was nil")
	}

	nsRaw := ctx.Value(contextNamespace)
	if nsRaw == nil {
		return nil, ErrNoNamespace
	}

	ns := nsRaw.(*Namespace)
	if ns == nil {
		return nil, ErrNoNamespace
	}

	return ns, nil
}
