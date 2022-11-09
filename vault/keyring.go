package vault

import "time"

// p37
type Keyring struct {
	rootKey        []byte
	keys           map[uint32]*Key
	activeTerm     uint32
	rotationConfig KeyRotationConfig
}

// p52
type Key struct {
	Term        uint32
	Version     int
	Value       []byte
	InstallTime time.Time
	Encryptions uint64 `json:"encryptions,omitempty"`
}

// p60
type KeyRotationConfig struct {
	Disabled      bool
	MaxOperations int64
	Interval      time.Duration
}
