package fairshare

import (
	"container/list"
	"log"
	"sync"

	"github.com/hashicorp/vault/helper/metricsutil"
)

type JobManager struct {
	name   string
	queues map[string]*list.List

	quit    chan struct{}
	newWork chan struct{} // must be buffered

	workerPool  *dispatcher
	workerCount map[string]int

	onceStart sync.Once
	onceStop  sync.Once

	logger log.Logger

	totalJobs  int
	metricSink *metricsutil.ClusterMetricSink

	wg sync.WaitGroup

	l sync.RWMutex

	queuesIndex       []string
	lastQueueAccessed int
}
