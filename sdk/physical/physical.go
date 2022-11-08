package physical

import (
	"context"

	log "github.com/hashicorp/go-hclog"
)

type Backend interface {
	// Put is used to insert or update an entry
	Put(ctx context.Context, entry *Entry) error

	// Get is used to fetch an entry
	Get(ctx context.Context, key string) (*Entry, error)

	// Delete is used to permanently delete an entry
	Delete(ctx context.Context, key string) error

	// List is used to list all the keys under a given
	// prefix, up to the next prefix.
	List(ctx context.Context, prefix string) ([]string, error)
}

type Factory func(config map[string]string, logger log.Logger) (Backend, error)
