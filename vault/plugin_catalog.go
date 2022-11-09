package vault

import (
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"google.golang.org/grpc"
)

// p42
type PluginCatalog struct {
	builtinRegistry BuiltinRegistry
	catalogView     *BarrierView
	directory       string
	logger          log.Logger

	externalPlugins map[externalPluginsKey]*externalPlugin
	mlockPlugins    bool

	lock sync.RWMutex
}

// p68
type externalPluginsKey struct {
	name    string
	typ     consts.PluginType
	version string
	command string
	args    string
	env     string
	sha256  string
	builtin bool
}

// p104
type externalPlugin struct {
	// connections holds client connections by ID
	connections map[string]*pluginClient

	multiplexingSupport bool
}

type pluginClient struct {
	logger log.Logger

	// id is the connection ID
	id  string
	pid int

	// client handles the lifecycle of a plugin process
	// multiplexed plugins share the same client
	client      *plugin.Client
	clientConn  grpc.ClientConnInterface
	cleanupFunc func() error
	reloadFunc  func() error

	plugin.ClientProtocol
}
