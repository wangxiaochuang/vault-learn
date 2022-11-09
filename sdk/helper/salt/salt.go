package salt

import "hash"

// p27
type Salt struct {
	config    *Config
	salt      string
	generated bool
}

type HashFunc func([]byte) []byte

type Config struct {
	Location string

	HashFunc HashFunc

	HMAC func() hash.Hash

	HMACType string
}
