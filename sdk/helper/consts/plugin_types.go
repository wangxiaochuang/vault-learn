package consts

import "fmt"

var PluginTypes = []PluginType{
	PluginTypeUnknown,
	PluginTypeCredential,
	PluginTypeDatabase,
	PluginTypeSecrets,
}

type PluginType uint32

const (
	PluginTypeUnknown PluginType = iota
	PluginTypeCredential
	PluginTypeDatabase
	PluginTypeSecrets
)

func (p PluginType) String() string {
	switch p {
	case PluginTypeUnknown:
		return "unknown"
	case PluginTypeCredential:
		return "auth"
	case PluginTypeDatabase:
		return "database"
	case PluginTypeSecrets:
		return "secret"
	default:
		return "unsupported"
	}
}

func ParsePluginType(pluginType string) (PluginType, error) {
	switch pluginType {
	case "unknown":
		return PluginTypeUnknown, nil
	case "auth":
		return PluginTypeCredential, nil
	case "database":
		return PluginTypeDatabase, nil
	case "secret":
		return PluginTypeSecrets, nil
	default:
		return PluginTypeUnknown, fmt.Errorf("%q is not a supported plugin type", pluginType)
	}
}
