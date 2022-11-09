package locksutil

import "sync"

const (
	LockCount = 256
)

type LockEntry struct {
	sync.RWMutex
}
