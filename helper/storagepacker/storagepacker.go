package storagepacker

import (
	"log"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// p30
type StoragePacker struct {
	view         logical.Storage
	logger       log.Logger
	storageLocks []*locksutil.LockEntry
	viewPrefix   string
}
