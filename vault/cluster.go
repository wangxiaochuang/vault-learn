package vault

import (
	"errors"
	"fmt"
	"net"
	"net/http"
)

const (
	// Storage path where the local cluster name and identifier are stored
	coreLocalClusterInfoPath = "core/cluster/local/info"

	corePrivateKeyTypeP521    = "p521"
	corePrivateKeyTypeED25519 = "ed25519"

	// Internal so as not to log a trace message
	IntNoForwardingHeaderName = "X-Vault-Internal-No-Request-Forwarding"
)

var (
	ErrCannotForward          = errors.New("cannot forward request; no connection or address not known")
	ErrCannotForwardLocalOnly = errors.New("cannot forward local-only request")
)

type ClusterLeaderParams struct {
	LeaderUUID         string
	LeaderRedirectAddr string
	LeaderClusterAddr  string
}

// p49
type Cluster struct {
	Name string `json:"name" structs:"name" mapstructure:"name"`
	ID   string `json:"id" structs:"id" mapstructure:"id"`
}

// p352
func (c *Core) ClusterAddr() string {
	return c.clusterAddr.Load().(string)
}

// p381
func (c *Core) SetClusterListenerAddrs(addrs []*net.TCPAddr) {
	c.clusterListenerAddrs = addrs
	if c.ClusterAddr() == "" && len(addrs) == 1 {
		c.clusterAddr.Store(fmt.Sprintf("https://%s", addrs[0].String()))
	}
}

func (c *Core) SetClusterHandler(handler http.Handler) {
	c.clusterHandler = handler
}
