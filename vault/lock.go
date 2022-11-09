//go:build !deadlock

package vault

import (
	"sync"
)

type DeadlockMutex struct {
	sync.Mutex
}

type DeadlockRWMutex struct {
	sync.RWMutex
}
