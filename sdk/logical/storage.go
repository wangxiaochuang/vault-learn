package logical

import "context"

type Storage interface {
	List(context.Context, string) ([]string, error)
	Get(context.Context, string) (*StorageEntry, error)
	Put(context.Context, *StorageEntry) error
	Delete(context.Context, string) error
}

type StorageEntry struct {
	Key      string
	Value    []byte
	SealWrap bool
}
