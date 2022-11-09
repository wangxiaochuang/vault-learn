package vault

import (
	"sync"
	"sync/atomic"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/metricsutil"
	"github.com/hashicorp/vault/vault/activity"
)

// p80
type segmentInfo struct {
	startTimestamp       int64
	currentClients       *activity.EntityActivityLog
	clientSequenceNumber uint64
	tokenCount           *activity.TokenCount
}

// p98
type ActivityLog struct {
	core            *Core
	configOverrides *ActivityLogCoreConfig

	// ActivityLog.l protects the configuration settings, except enable, and any modifications
	// to the current segment.
	// Acquire "l" before fragmentLock if both must be held.
	l sync.RWMutex

	// fragmentLock protects enable, partialMonthClientTracker, fragment,
	// standbyFragmentsReceived.
	fragmentLock sync.RWMutex

	// enabled indicates if the activity log is enabled for this cluster.
	// This is protected by fragmentLock so we can check with only
	// a single synchronization call.
	enabled bool

	// log destination
	logger log.Logger

	// metrics sink
	metrics metricsutil.Metrics

	// view is the storage location used by ActivityLog,
	// defaults to sys/activity.
	view *BarrierView

	// nodeID is the ID to use for all fragments that
	// are generated.
	// TODO: use secondary ID when available?
	nodeID string

	// current log fragment (may be nil)
	fragment         *activity.LogFragment
	fragmentCreation time.Time

	// Channel to signal a new fragment has been created
	// so it's appropriate to start the timer.
	newFragmentCh chan struct{}

	// Channel for sending fragment immediately
	sendCh chan struct{}

	// Channel for writing fragment immediately
	writeCh chan struct{}

	// Channel to stop background processing
	doneCh chan struct{}

	// track metadata and contents of the most recent log segment
	currentSegment segmentInfo

	// Fragments received from performance standbys
	standbyFragmentsReceived []*activity.LogFragment

	// precomputed queries
	queryStore          *activity.PrecomputedQueryStore
	defaultReportMonths int
	retentionMonths     int

	// channel closed by delete worker when done
	deleteDone chan struct{}

	// channel closed when deletion at startup is done
	// (for unit test robustness)
	retentionDone         chan struct{}
	computationWorkerDone chan struct{}

	// for testing: is config currently being invalidated. protected by l
	configInvalidationInProgress bool

	// partialMonthClientTracker tracks active clients this month.  Protected by fragmentLock.
	partialMonthClientTracker map[string]*activity.EntityRecord

	inprocessExport *atomic.Bool
}

// p179
type ActivityLogCoreConfig struct {
	// Enable activity log even if the feature flag not set
	ForceEnable bool

	// Do not start timers to send or persist fragments.
	DisableTimers bool
}
