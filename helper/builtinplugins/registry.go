package builtinplugins

import (
	logicalKv "github.com/hashicorp/vault-plugin-secrets-kv"
	credUserpass "github.com/hashicorp/vault/builtin/credential/userpass"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

// p65
var Registry = newRegistry()

var addExternalPlugins = addExtPluginsImpl

type BuiltinFactory func() (interface{}, error)

// There are three forms of Backends which exist in the BuiltinRegistry.
type credentialBackend struct {
	logical.Factory
	consts.DeprecationStatus
}

type databasePlugin struct {
	Factory BuiltinFactory
	consts.DeprecationStatus
}

type logicalBackend struct {
	logical.Factory
	consts.DeprecationStatus
}

func newRegistry() *registry {
	reg := &registry{
		credentialBackends: map[string]credentialBackend{
			"userpass": {Factory: credUserpass.Factory},
		},
		databasePlugins: map[string]databasePlugin{},
		logicalBackends: map[string]logicalBackend{
			"kv": {Factory: logicalKv.Factory},
		},
	}
	addExternalPlugins(reg)

	return reg
}

func addExtPluginsImpl(r *registry) {}

type registry struct {
	credentialBackends map[string]credentialBackend
	databasePlugins    map[string]databasePlugin
	logicalBackends    map[string]logicalBackend
}

func (r *registry) Get(name string, pluginType consts.PluginType) (func() (interface{}, error), bool) {
	switch pluginType {
	case consts.PluginTypeCredential:
		if f, ok := r.credentialBackends[name]; ok {
			return toFunc(f.Factory), ok
		}
	case consts.PluginTypeSecrets:
		if f, ok := r.logicalBackends[name]; ok {
			return toFunc(f.Factory), ok
		}
	case consts.PluginTypeDatabase:
		if f, ok := r.databasePlugins[name]; ok {
			return f.Factory, ok
		}
	default:
		return nil, false
	}

	return nil, false
}

// Keys returns the list of plugin names that are considered builtin plugins.
func (r *registry) Keys(pluginType consts.PluginType) []string {
	panic("not implement")
}

func (r *registry) Contains(name string, pluginType consts.PluginType) bool {
	panic("not implement")
}

// DeprecationStatus returns the Deprecation status for a builtin with type `pluginType`
func (r *registry) DeprecationStatus(name string, pluginType consts.PluginType) (consts.DeprecationStatus, bool) {
	panic("not implement")
}

func toFunc(ifc interface{}) func() (interface{}, error) {
	return func() (interface{}, error) {
		return ifc, nil
	}
}
