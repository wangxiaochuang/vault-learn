package quotas

import (
	"context"
	"log"
	"sync"

	"github.com/hashicorp/go-memdb"
	"github.com/hashicorp/vault/helper/metricsutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// p151
type Manager struct {
	entManager

	// db holds the in memory instances of all active quota rules indexed by
	// some of the quota properties.
	db *memdb.MemDB

	// config containing operator preferences and quota behaviors
	config *Config

	rateLimitPathManager *pathmanager.PathManager

	storage logical.Storage
	ctx     context.Context

	logger     log.Logger
	metricSink *metricsutil.ClusterMetricSink
	lock       *sync.RWMutex
}
