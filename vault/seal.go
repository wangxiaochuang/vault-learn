package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/vault/vault/seal"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

const (
	barrierSealConfigPath = "core/seal-config"

	recoverySealConfigPath = "core/recovery-seal-config"

	recoverySealConfigPlaintextPath = "core/recovery-config"

	recoveryKeyPath = "core/recovery-key"

	StoredBarrierKeysPath = "core/hsm/barrier-unseal-keys"
	hsmStoredIVPath       = "core/hsm/iv"
)

const (
	RecoveryTypeUnsupported = "unsupported"
	RecoveryTypeShamir      = "shamir"
)

// p54
type Seal interface {
	SetCore(*Core)
	Init(context.Context) error
	Finalize(context.Context) error
	StoredKeysSupported() seal.StoredKeysSupport
	SealWrapable() bool
	SetStoredKeys(context.Context, [][]byte) error
	GetStoredKeys(context.Context) ([][]byte, error)
	BarrierType() wrapping.WrapperType
	BarrierConfig(context.Context) (*SealConfig, error)
	SetBarrierConfig(context.Context, *SealConfig) error
	SetCachedBarrierConfig(*SealConfig)
	RecoveryKeySupported() bool
	RecoveryType() string
	RecoveryConfig(context.Context) (*SealConfig, error)
	RecoveryKey(context.Context) ([]byte, error)
	SetRecoveryConfig(context.Context, *SealConfig) error
	SetCachedRecoveryConfig(*SealConfig)
	SetRecoveryKey(context.Context, []byte) error
	VerifyRecoveryKey(context.Context, []byte) error
	GetAccess() *seal.Access
}

// p77
type defaultSeal struct {
	access *seal.Access
	config atomic.Value
	core   *Core
}

// p83
func NewDefaultSeal(lowLevel *seal.Access) Seal {
	ret := &defaultSeal{
		access: lowLevel,
	}
	ret.config.Store((*SealConfig)(nil))
	return ret
}

func (d *defaultSeal) SealWrapable() bool {
	return false
}

func (d *defaultSeal) checkCore() error {
	if d.core == nil {
		return fmt.Errorf("seal does not have a core set")
	}
	return nil
}

func (d *defaultSeal) GetAccess() *seal.Access {
	return d.access
}

func (d *defaultSeal) SetAccess(access *seal.Access) {
	d.access = access
}

func (d *defaultSeal) SetCore(core *Core) {
	d.core = core
}

func (d *defaultSeal) Init(ctx context.Context) error {
	return nil
}

func (d *defaultSeal) Finalize(ctx context.Context) error {
	return nil
}

func (d *defaultSeal) BarrierType() wrapping.WrapperType {
	return wrapping.WrapperTypeShamir
}

func (d *defaultSeal) StoredKeysSupported() seal.StoredKeysSupport {
	switch {
	case d.LegacySeal():
		return seal.StoredKeysNotSupported
	default:
		return seal.StoredKeysSupportedShamirRoot
	}
}

func (d *defaultSeal) RecoveryKeySupported() bool {
	return false
}

func (d *defaultSeal) SetStoredKeys(ctx context.Context, keys [][]byte) error {
	panic("not implement")
}

func (d *defaultSeal) LegacySeal() bool {
	panic("not implement")
}

func (d *defaultSeal) GetStoredKeys(ctx context.Context) ([][]byte, error) {
	panic("not implement")
}

func (d *defaultSeal) BarrierConfig(ctx context.Context) (*SealConfig, error) {
	panic("not implement")
}

func (d *defaultSeal) SetBarrierConfig(ctx context.Context, config *SealConfig) error {
	panic("not implement")
}

func (d *defaultSeal) SetCachedBarrierConfig(config *SealConfig) {
	d.config.Store(config)
}

func (d *defaultSeal) RecoveryType() string {
	panic("not implement")
}

func (d *defaultSeal) RecoveryConfig(ctx context.Context) (*SealConfig, error) {
	return nil, fmt.Errorf("recovery not supported")
}

func (d *defaultSeal) RecoveryKey(ctx context.Context) ([]byte, error) {
	return nil, fmt.Errorf("recovery not supported")
}

func (d *defaultSeal) SetRecoveryConfig(ctx context.Context, config *SealConfig) error {
	return fmt.Errorf("recovery not supported")
}

func (d *defaultSeal) SetCachedRecoveryConfig(config *SealConfig) {
}

func (d *defaultSeal) VerifyRecoveryKey(ctx context.Context, key []byte) error {
	return fmt.Errorf("recovery not supported")
}

func (d *defaultSeal) SetRecoveryKey(ctx context.Context, key []byte) error {
	return fmt.Errorf("recovery not supported")
}

// p288
type SealConfig struct {
	Type                 string   `json:"type" mapstructure:"type"`
	SecretShares         int      `json:"secret_shares" mapstructure:"secret_shares"`
	SecretThreshold      int      `json:"secret_threshold" mapstructure:"secret_threshold"`
	PGPKeys              []string `json:"pgp_keys" mapstructure:"pgp_keys"`
	Nonce                string   `json:"nonce" mapstructure:"nonce"`
	Backup               bool     `json:"backup" mapstructure:"backup"`
	StoredShares         int      `json:"stored_shares" mapstructure:"stored_shares"`
	RekeyProgress        [][]byte `json:"-"`
	VerificationRequired bool     `json:"-"`
	VerificationKey      []byte   `json:"-"`
	VerificationNonce    string   `json:"-"`
	VerificationProgress [][]byte `json:"-"`
}

// p339
func (s *SealConfig) Validate() error {
	if s.SecretShares < 1 {
		return fmt.Errorf("shares must be at least one")
	}
	if s.SecretThreshold < 1 {
		return fmt.Errorf("threshold must be at least one")
	}
	if s.SecretShares > 1 && s.SecretThreshold == 1 {
		return fmt.Errorf("threshold must be greater than one for multiple shares")
	}
	if s.SecretShares > 255 {
		return fmt.Errorf("shares must be less than 256")
	}
	if s.SecretThreshold > 255 {
		return fmt.Errorf("threshold must be less than 256")
	}
	if s.SecretThreshold > s.SecretShares {
		return fmt.Errorf("threshold cannot be larger than shares")
	}
	if s.StoredShares > 1 {
		return fmt.Errorf("stored keys cannot be larger than 1")
	}
	if len(s.PGPKeys) > 0 && len(s.PGPKeys) != s.SecretShares {
		return fmt.Errorf("count mismatch between number of provided PGP keys and number of shares")
	}
	if len(s.PGPKeys) > 0 {
		for _, keystring := range s.PGPKeys {
			data, err := base64.StdEncoding.DecodeString(keystring)
			if err != nil {
				return fmt.Errorf("error decoding given PGP key: %w", err)
			}
			_, err = openpgp.ReadEntity(packet.NewReader(bytes.NewBuffer(data)))
			if err != nil {
				return fmt.Errorf("error parsing given PGP key: %w", err)
			}
		}
	}
	return nil
}

func (s *SealConfig) Clone() *SealConfig {
	ret := &SealConfig{
		Type:                 s.Type,
		SecretShares:         s.SecretShares,
		SecretThreshold:      s.SecretThreshold,
		Nonce:                s.Nonce,
		Backup:               s.Backup,
		StoredShares:         s.StoredShares,
		VerificationRequired: s.VerificationRequired,
		VerificationNonce:    s.VerificationNonce,
	}
	if len(s.PGPKeys) > 0 {
		ret.PGPKeys = make([]string, len(s.PGPKeys))
		copy(ret.PGPKeys, s.PGPKeys)
	}
	if len(s.VerificationKey) > 0 {
		ret.VerificationKey = make([]byte, len(s.VerificationKey))
		copy(ret.VerificationKey, s.VerificationKey)
	}
	return ret
}

type ErrEncrypt struct {
	Err error
}

var _ error = &ErrEncrypt{}

func (e *ErrEncrypt) Error() string {
	return e.Err.Error()
}

func (e *ErrEncrypt) Is(target error) bool {
	_, ok := target.(*ErrEncrypt)
	return ok || errors.Is(e.Err, target)
}

type ErrDecrypt struct {
	Err error
}

var _ error = &ErrDecrypt{}

func (e *ErrDecrypt) Error() string {
	return e.Err.Error()
}

func (e *ErrDecrypt) Is(target error) bool {
	_, ok := target.(*ErrDecrypt)
	return ok || errors.Is(e.Err, target)
}
