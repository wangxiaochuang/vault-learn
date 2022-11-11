package vault

import "time"

const (
	absoluteOperationMaximum = int64(3_865_470_566)
	absoluteOperationMinimum = int64(1_000_000)
	minimumRotationInterval  = 24 * time.Hour
)

var (
	defaultRotationConfig = KeyRotationConfig{
		MaxOperations: absoluteOperationMaximum,
	}
	disabledRotationConfig = KeyRotationConfig{
		Disabled: true,
	}
)

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

func (k *Keyring) Clone() *Keyring {
	clone := &Keyring{
		rootKey:        k.rootKey,
		keys:           make(map[uint32]*Key, len(k.keys)),
		activeTerm:     k.activeTerm,
		rotationConfig: k.rotationConfig,
	}
	for idx, key := range k.keys {
		clone.keys[idx] = key
	}
	return clone
}

// p243
func (c KeyRotationConfig) Clone() KeyRotationConfig {
	clone := KeyRotationConfig{
		MaxOperations: c.MaxOperations,
		Interval:      c.Interval,
		Disabled:      c.Disabled,
	}

	clone.Sanitize()
	return clone
}

func (c *KeyRotationConfig) Sanitize() {
	if c.MaxOperations == 0 || c.MaxOperations > absoluteOperationMaximum {
		c.MaxOperations = absoluteOperationMaximum
	}
	if c.MaxOperations < absoluteOperationMinimum {
		c.MaxOperations = absoluteOperationMinimum
	}
	if c.Interval > 0 && c.Interval < minimumRotationInterval {
		c.Interval = minimumRotationInterval
	}
}

func (c *KeyRotationConfig) Equals(config KeyRotationConfig) bool {
	return c.MaxOperations == config.MaxOperations && c.Interval == config.Interval
}
