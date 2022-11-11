package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
	"go.uber.org/atomic"
)

// p40
const (
	AESGCMVersion1 = 0x1
	AESGCMVersion2 = 0x2
)

// p63
type AESGCMBarrier struct {
	backend physical.Backend

	l      sync.RWMutex
	sealed bool

	keyring *Keyring

	cache     map[uint32]cipher.AEAD
	cacheLock sync.RWMutex

	currentAESGCMVersionByte byte

	initialized atomic.Bool

	UnaccountedEncryptions *atomic.Int64
	RemoteEncryptions      *atomic.Int64
	totalLocalEncryptions  *atomic.Int64
}

func (b *AESGCMBarrier) RotationConfig() (kc KeyRotationConfig, err error) {
	if b.keyring == nil {
		return kc, errors.New("keyring not yet present")
	}
	return b.keyring.rotationConfig.Clone(), nil
}

func (b *AESGCMBarrier) SetRotationConfig(ctx context.Context, rotConfig KeyRotationConfig) error {
	b.l.Lock()
	defer b.l.Unlock()
	rotConfig.Sanitize()
	if !rotConfig.Equals(b.keyring.rotationConfig) {
		b.keyring.rotationConfig = rotConfig

		return b.persistKeyring(ctx, b.keyring)
	}
	return nil
}

// p112
func NewAESGCMBarrier(physical physical.Backend) (*AESGCMBarrier, error) {
	b := &AESGCMBarrier{
		backend:                  physical,
		sealed:                   true,
		cache:                    make(map[uint32]cipher.AEAD),
		currentAESGCMVersionByte: byte(AESGCMVersion2),
		UnaccountedEncryptions:   atomic.NewInt64(0),
		RemoteEncryptions:        atomic.NewInt64(0),
		totalLocalEncryptions:    atomic.NewInt64(0),
	}
	return b, nil
}

// p127
func (b *AESGCMBarrier) Initialized(ctx context.Context) (bool, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) Initialize(ctx context.Context, key, sealKey []byte, reader io.Reader) error {
	panic("not implement")
}

// p210
func (b *AESGCMBarrier) persistKeyring(ctx context.Context, keyring *Keyring) error {
	panic("not implement")
}

// GenerateKey is used to generate a new key
func (b *AESGCMBarrier) GenerateKey(reader io.Reader) ([]byte, error) {
	// Generate a 256bit key
	buf := make([]byte, 2*aes.BlockSize)
	_, err := reader.Read(buf)

	return buf, err
}

// KeyLength is used to sanity check a key
func (b *AESGCMBarrier) KeyLength() (int, int) {
	return aes.BlockSize, 2 * aes.BlockSize
}

func (b *AESGCMBarrier) Sealed() (bool, error) {
	b.l.RLock()
	sealed := b.sealed
	b.l.RUnlock()
	return sealed, nil
}

func (b *AESGCMBarrier) VerifyRoot(key []byte) error {
	panic("not implement")
}

func (b *AESGCMBarrier) ReloadKeyring(ctx context.Context) error {
	panic("not implement")
}

func (b *AESGCMBarrier) recoverKeyring(plaintext []byte) error {
	panic("not implement")
}

func (b *AESGCMBarrier) ReloadRootKey(ctx context.Context) error {
	panic("not implement")
}

func (b *AESGCMBarrier) Unseal(ctx context.Context, key []byte) error {
	panic("not implement")
}

func (b *AESGCMBarrier) Seal() error {
	panic("not implement")
}

func (b *AESGCMBarrier) Rotate(ctx context.Context, randomSource io.Reader) (uint32, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) CreateUpgrade(ctx context.Context, term uint32) error {
	panic("not implement")
}

func (b *AESGCMBarrier) DestroyUpgrade(ctx context.Context, term uint32) error {
	path := fmt.Sprintf("%s%d", keyringUpgradePrefix, term-1)
	return b.Delete(ctx, path)
}

func (b *AESGCMBarrier) CheckUpgrade(ctx context.Context) (bool, uint32, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) ActiveKeyInfo() (*KeyInfo, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) Rekey(ctx context.Context, key []byte) error {
	panic("not implement")
}

func (b *AESGCMBarrier) SetRootKey(key []byte) error {
	panic("not implement")
}

func (b *AESGCMBarrier) updateRootKeyCommon(key []byte) (*Keyring, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) Put(ctx context.Context, entry *logical.StorageEntry) error {
	panic("not implement")
}

func (b *AESGCMBarrier) putInternal(ctx context.Context, term uint32, primary cipher.AEAD, entry *logical.StorageEntry) error {
	panic("not implement")
}

func (b *AESGCMBarrier) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	return b.lockSwitchedGet(ctx, key, true)
}

func (b *AESGCMBarrier) lockSwitchedGet(ctx context.Context, key string, getLock bool) (*logical.StorageEntry, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) Delete(ctx context.Context, key string) error {
	panic("not implement")
}

func (b *AESGCMBarrier) List(ctx context.Context, prefix string) ([]string, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) aeadForTerm(term uint32) (cipher.AEAD, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) encrypt(path string, term uint32, gcm cipher.AEAD, plain []byte) ([]byte, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) decrypt(path string, gcm cipher.AEAD, cipher []byte) ([]byte, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) Encrypt(ctx context.Context, key string, plaintext []byte) ([]byte, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) Decrypt(_ context.Context, key string, ciphertext []byte) ([]byte, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) Keyring() (*Keyring, error) {
	b.l.RLock()
	defer b.l.RUnlock()
	if b.sealed {
		return nil, ErrBarrierSealed
	}

	return b.keyring.Clone(), nil
}

func (b *AESGCMBarrier) ConsumeEncryptionCount(consumer func(int64) error) error {
	panic("not implement")
}

func (b *AESGCMBarrier) AddRemoteEncryptions(encryptions int64) {
	panic("not implement")
}

func (b *AESGCMBarrier) encryptTracked(path string, term uint32, gcm cipher.AEAD, buf []byte) ([]byte, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) TotalLocalEncryptions() int64 {
	return b.totalLocalEncryptions.Load()
}

func (b *AESGCMBarrier) CheckBarrierAutoRotate(ctx context.Context) (string, error) {
	panic("not implement")
}

func (b *AESGCMBarrier) persistEncryptions(ctx context.Context) error {
	panic("not implement")
}

func (b *AESGCMBarrier) encryptions() int64 {
	panic("not implement")
}
