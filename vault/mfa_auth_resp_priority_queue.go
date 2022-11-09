package vault

import (
	"sync"

	"github.com/hashicorp/vault/sdk/queue"
)

// p20
type LoginMFAPriorityQueue struct {
	wrapped *queue.PriorityQueue

	l sync.RWMutex
}
