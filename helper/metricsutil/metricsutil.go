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

// p56
func NewMetricsHelper(inMem *metrics.InmemSink, enablePrometheus bool) *MetricsHelper {
	return &MetricsHelper{inMem, enablePrometheus, GaugeMetrics{Metrics: sync.Map{}}}
}
