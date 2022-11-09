package vault

import (
	"context"
	"io"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// p76
type SecurityBarrier interface {
	Initialized(ctx context.Context) (bool, error)

	Initialize(ctx context.Context, rootKey []byte, sealKey []byte, random io.Reader) error

	GenerateKey(io.Reader) ([]byte, error)

	KeyLength() (int, int)

	Sealed() (bool, error)

	Unseal(ctx context.Context, key []byte) error

	VerifyRoot(key []byte) error

	SetRootKey(key []byte) error

	ReloadKeyring(ctx context.Context) error

	ReloadRootKey(ctx context.Context) error

	Seal() error

	Rotate(ctx context.Context, reader io.Reader) (uint32, error)

	CreateUpgrade(ctx context.Context, term uint32) error

	DestroyUpgrade(ctx context.Context, term uint32) error

	CheckUpgrade(ctx context.Context) (bool, uint32, error)

	ActiveKeyInfo() (*KeyInfo, error)

	RotationConfig() (KeyRotationConfig, error)

	SetRotationConfig(ctx context.Context, config KeyRotationConfig) error

	Rekey(context.Context, []byte) error

	Keyring() (*Keyring, error)

	ConsumeEncryptionCount(consumer func(int64) error) error

	AddRemoteEncryptions(encryptions int64)

	CheckBarrierAutoRotate(ctx context.Context) (string, error)

	logical.Storage

	BarrierEncryptor
}

// p187
type BarrierEncryptor interface {
	Encrypt(ctx context.Context, key string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, key string, ciphertext []byte) ([]byte, error)
}

type KeyInfo struct {
	Term        int
	InstallTime time.Time
	Encryptions int64
}
