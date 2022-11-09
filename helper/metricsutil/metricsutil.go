package metricsutil

import (
	"sync"

	"github.com/armon/go-metrics"
)

// p36
type MetricsHelper struct {
	inMemSink         *metrics.InmemSink
	PrometheusEnabled bool
	LoopMetrics       GaugeMetrics
}

type GaugeMetrics struct {
	Metrics sync.Map
}
