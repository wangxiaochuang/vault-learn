package metricsutil

import (
	"sync/atomic"
	"time"

	"github.com/armon/go-metrics"
)

// p18
type ClusterMetricSink struct {
	ClusterName atomic.Value

	MaxGaugeCardinality int
	GaugeInterval       time.Duration

	// Sink is the go-metrics instance to send to.
	Sink metrics.MetricSink

	// Constants that are helpful for metrics within the metrics sink
	TelemetryConsts TelemetryConstConfig
}

type TelemetryConstConfig struct {
	LeaseMetricsEpsilon         time.Duration
	NumLeaseMetricsTimeBuckets  int
	LeaseMetricsNameSpaceLabels bool
}

// p42
type Metrics interface {
	SetGaugeWithLabels(key []string, val float32, labels []Label)
	IncrCounterWithLabels(key []string, val float32, labels []Label)
	AddSampleWithLabels(key []string, val float32, labels []Label)
	AddDurationWithLabels(key []string, d time.Duration, labels []Label)
	MeasureSinceWithLabels(key []string, start time.Time, labels []Label)
}

// p72
type Label = metrics.Label
