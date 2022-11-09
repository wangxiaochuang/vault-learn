package vault

// p28
type (
	entCore       struct{}
	entCoreConfig struct{}
)

func (e entCoreConfig) Clone() entCoreConfig {
	return entCoreConfig{}
}

type LicensingConfig struct {
	AdditionalPublicKeys []interface{}
}
