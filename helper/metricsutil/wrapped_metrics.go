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

func (m *ClusterMetricSink) SetGauge(key []string, val float32) {
	m.Sink.SetGaugeWithLabels(key, val, []Label{{"cluster", m.ClusterName.Load().(string)}})
}

func (m *ClusterMetricSink) SetGaugeWithLabels(key []string, val float32, labels []Label) {
	m.Sink.SetGaugeWithLabels(key, val,
		append(labels, Label{"cluster", m.ClusterName.Load().(string)}))
}

func (m *ClusterMetricSink) IncrCounterWithLabels(key []string, val float32, labels []Label) {
	m.Sink.IncrCounterWithLabels(key, val,
		append(labels, Label{"cluster", m.ClusterName.Load().(string)}))
}

func (m *ClusterMetricSink) AddSample(key []string, val float32) {
	m.Sink.AddSampleWithLabels(key, val, []Label{{"cluster", m.ClusterName.Load().(string)}})
}

func (m *ClusterMetricSink) AddSampleWithLabels(key []string, val float32, labels []Label) {
	m.Sink.AddSampleWithLabels(key, val,
		append(labels, Label{"cluster", m.ClusterName.Load().(string)}))
}

func (m *ClusterMetricSink) AddDurationWithLabels(key []string, d time.Duration, labels []Label) {
	val := float32(d) / float32(time.Millisecond)
	m.AddSampleWithLabels(key, val, labels)
}

func (m *ClusterMetricSink) MeasureSinceWithLabels(key []string, start time.Time, labels []Label) {
	elapsed := time.Now().Sub(start)
	val := float32(elapsed) / float32(time.Millisecond)
	m.AddSampleWithLabels(key, val, labels)
}

// p109
func BlackholeSink() *ClusterMetricSink {
	conf := metrics.DefaultConfig("")
	conf.EnableRuntimeMetrics = false
	sink, _ := metrics.New(conf, &metrics.BlackholeSink{})
	cms := &ClusterMetricSink{
		ClusterName: atomic.Value{},
		Sink:        sink,
	}
	cms.ClusterName.Store("")
	return cms
}

// p121
func NewClusterMetricSink(clusterName string, sink metrics.MetricSink) *ClusterMetricSink {
	cms := &ClusterMetricSink{
		ClusterName:     atomic.Value{},
		Sink:            sink,
		TelemetryConsts: TelemetryConstConfig{},
	}
	cms.ClusterName.Store(clusterName)
	return cms
}
