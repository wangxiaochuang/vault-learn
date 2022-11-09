package vault

import (
	"context"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/vault/vault/seal"
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
