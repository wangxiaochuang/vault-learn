package vault

import "context"

// p31
type GenerateRootStrategy interface {
	generate(context.Context, *Core) (string, func(), error)
	authenticate(context.Context, *Core, []byte) error
}

// p72
type GenerateRootConfig struct {
	Nonce          string
	PGPKey         string
	PGPFingerprint string
	OTP            string
	Strategy       GenerateRootStrategy
}
