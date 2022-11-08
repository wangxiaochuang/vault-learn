package configutil

import (
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

const (
	PrometheusDefaultRetentionTime    = 24 * time.Hour
	UsageGaugeDefaultPeriod           = 10 * time.Minute
	MaximumGaugeCardinalityDefault    = 500
	LeaseMetricsEpsilonDefault        = time.Hour
	NumLeaseMetricsTimeBucketsDefault = 168
)

type Telemetry struct {
	FoundKeys    []string     `hcl:",decodedFields"`
	UnusedKeys   UnusedKeyMap `hcl:",unusedKeyPositions"`
	StatsiteAddr string       `hcl:"statsite_address"`
	StatsdAddr   string       `hcl:"statsd_address"`

	DisableHostname     bool   `hcl:"disable_hostname"`
	EnableHostnameLabel bool   `hcl:"enable_hostname_label"`
	MetricsPrefix       string `hcl:"metrics_prefix"`
	UsageGaugePeriod    time.Duration
	UsageGaugePeriodRaw interface{} `hcl:"usage_gauge_period,alias:UsageGaugePeriod"`

	MaximumGaugeCardinality int `hcl:"maximum_gauge_cardinality"`

	// Circonus: see https://github.com/circonus-labs/circonus-gometrics
	// for more details on the various configuration options.
	// Valid configuration combinations:
	//    - CirconusAPIToken
	//      metric management enabled (search for existing check or create a new one)
	//    - CirconusSubmissionUrl
	//      metric management disabled (use check with specified submission_url,
	//      broker must be using a public SSL certificate)
	//    - CirconusAPIToken + CirconusCheckSubmissionURL
	//      metric management enabled (use check with specified submission_url)
	//    - CirconusAPIToken + CirconusCheckID
	//      metric management enabled (use check with specified id)

	// CirconusAPIToken is a valid API Token used to create/manage check. If provided,
	// metric management is enabled.
	// Default: none
	CirconusAPIToken string `hcl:"circonus_api_token"`
	// CirconusAPIApp is an app name associated with API token.
	// Default: "consul"
	CirconusAPIApp string `hcl:"circonus_api_app"`
	// CirconusAPIURL is the base URL to use for contacting the Circonus API.
	// Default: "https://api.circonus.com/v2"
	CirconusAPIURL string `hcl:"circonus_api_url"`
	// CirconusSubmissionInterval is the interval at which metrics are submitted to Circonus.
	// Default: 10s
	CirconusSubmissionInterval string `hcl:"circonus_submission_interval"`
	// CirconusCheckSubmissionURL is the check.config.submission_url field from a
	// previously created HTTPTRAP check.
	// Default: none
	CirconusCheckSubmissionURL string `hcl:"circonus_submission_url"`
	// CirconusCheckID is the check id (not check bundle id) from a previously created
	// HTTPTRAP check. The numeric portion of the check._cid field.
	// Default: none
	CirconusCheckID string `hcl:"circonus_check_id"`
	// CirconusCheckForceMetricActivation will force enabling metrics, as they are encountered,
	// if the metric already exists and is NOT active. If check management is enabled, the default
	// behavior is to add new metrics as they are encountered. If the metric already exists in the
	// check, it will *NOT* be activated. This setting overrides that behavior.
	// Default: "false"
	CirconusCheckForceMetricActivation string `hcl:"circonus_check_force_metric_activation"`
	// CirconusCheckInstanceID serves to uniquely identify the metrics coming from this "instance".
	// It can be used to maintain metric continuity with transient or ephemeral instances as
	// they move around within an infrastructure.
	// Default: hostname:app
	CirconusCheckInstanceID string `hcl:"circonus_check_instance_id"`
	// CirconusCheckSearchTag is a special tag which, when coupled with the instance id, helps to
	// narrow down the search results when neither a Submission URL or Check ID is provided.
	// Default: service:app (e.g. service:consul)
	CirconusCheckSearchTag string `hcl:"circonus_check_search_tag"`
	// CirconusCheckTags is a comma separated list of tags to apply to the check. Note that
	// the value of CirconusCheckSearchTag will always be added to the check.
	// Default: none
	CirconusCheckTags string `hcl:"circonus_check_tags"`
	// CirconusCheckDisplayName is the name for the check which will be displayed in the Circonus UI.
	// Default: value of CirconusCheckInstanceID
	CirconusCheckDisplayName string `hcl:"circonus_check_display_name"`
	// CirconusBrokerID is an explicit broker to use when creating a new check. The numeric portion
	// of broker._cid. If metric management is enabled and neither a Submission URL nor Check ID
	// is provided, an attempt will be made to search for an existing check using Instance ID and
	// Search Tag. If one is not found, a new HTTPTRAP check will be created.
	// Default: use Select Tag if provided, otherwise, a random Enterprise Broker associated
	// with the specified API token or the default Circonus Broker.
	// Default: none
	CirconusBrokerID string `hcl:"circonus_broker_id"`
	// CirconusBrokerSelectTag is a special tag which will be used to select a broker when
	// a Broker ID is not provided. The best use of this is to as a hint for which broker
	// should be used based on *where* this particular instance is running.
	// (e.g. a specific geo location or datacenter, dc:sfo)
	// Default: none
	CirconusBrokerSelectTag string `hcl:"circonus_broker_select_tag"`

	// Dogstats:
	// DogStatsdAddr is the address of a dogstatsd instance. If provided,
	// metrics will be sent to that instance
	DogStatsDAddr string `hcl:"dogstatsd_addr"`

	// DogStatsdTags are the global tags that should be sent with each packet to dogstatsd
	// It is a list of strings, where each string looks like "my_tag_name:my_tag_value"
	DogStatsDTags []string `hcl:"dogstatsd_tags"`

	// Prometheus:
	// PrometheusRetentionTime is the retention time for prometheus metrics if greater than 0.
	// Default: 24h
	PrometheusRetentionTime    time.Duration `hcl:"-"`
	PrometheusRetentionTimeRaw interface{}   `hcl:"prometheus_retention_time"`

	// Stackdriver:
	// StackdriverProjectID is the project to publish stackdriver metrics to.
	StackdriverProjectID string `hcl:"stackdriver_project_id"`
	// StackdriverLocation is the GCP or AWS region of the monitored resource.
	StackdriverLocation string `hcl:"stackdriver_location"`
	// StackdriverNamespace is the namespace identifier, such as a cluster name.
	StackdriverNamespace string `hcl:"stackdriver_namespace"`
	// StackdriverDebugLogs will write additional stackdriver related debug logs to stderr.
	StackdriverDebugLogs bool `hcl:"stackdriver_debug_logs"`

	// How often metrics for lease expiry will be aggregated
	LeaseMetricsEpsilon    time.Duration
	LeaseMetricsEpsilonRaw interface{} `hcl:"lease_metrics_epsilon"`

	// Number of buckets by time that will be used in lease aggregation
	NumLeaseMetricsTimeBuckets int `hcl:"num_lease_metrics_buckets"`

	// Whether or not telemetry should add labels for namespaces
	LeaseMetricsNameSpaceLabels bool `hcl:"add_lease_metrics_namespace_labels"`

	// FilterDefault is the default for whether to allow a metric that's not
	// covered by the prefix filter.
	FilterDefault *bool `hcl:"filter_default"`

	// PrefixFilter is a list of filter rules to apply for allowing
	// or blocking metrics by prefix.
	PrefixFilter []string `hcl:"prefix_filter"`
}

// p164
func (t *Telemetry) Validate(source string) []ConfigError {
	return ValidateUnusedFields(t.UnusedKeys, source)
}

func (t *Telemetry) GoString() string {
	return fmt.Sprintf("*%#v", *t)
}

// p172
func parseTelemetry(result *SharedConfig, list *ast.ObjectList) error {
	if len(list.Items) > 1 {
		return fmt.Errorf("only one 'telemetry' block is permitted")
	}

	// Get our one item
	item := list.Items[0]

	if result.Telemetry == nil {
		result.Telemetry = &Telemetry{}
	}

	if err := hcl.DecodeObject(&result.Telemetry, item.Val); err != nil {
		return multierror.Prefix(err, "telemetry:")
	}

	if result.Telemetry.PrometheusRetentionTimeRaw != nil {
		var err error
		if result.Telemetry.PrometheusRetentionTime, err = parseutil.ParseDurationSecond(result.Telemetry.PrometheusRetentionTimeRaw); err != nil {
			return err
		}
		result.Telemetry.PrometheusRetentionTimeRaw = nil
	} else {
		result.Telemetry.PrometheusRetentionTime = PrometheusDefaultRetentionTime
	}

	if result.Telemetry.UsageGaugePeriodRaw != nil {
		if result.Telemetry.UsageGaugePeriodRaw == "none" {
			result.Telemetry.UsageGaugePeriod = 0
		} else {
			var err error
			if result.Telemetry.UsageGaugePeriod, err = parseutil.ParseDurationSecond(result.Telemetry.UsageGaugePeriodRaw); err != nil {
				return err
			}
			result.Telemetry.UsageGaugePeriodRaw = nil
		}
	} else {
		result.Telemetry.UsageGaugePeriod = UsageGaugeDefaultPeriod
	}

	if result.Telemetry.MaximumGaugeCardinality == 0 {
		result.Telemetry.MaximumGaugeCardinality = MaximumGaugeCardinalityDefault
	}

	if result.Telemetry.LeaseMetricsEpsilonRaw != nil {
		if result.Telemetry.LeaseMetricsEpsilonRaw == "none" {
			result.Telemetry.LeaseMetricsEpsilonRaw = 0
		} else {
			var err error
			if result.Telemetry.LeaseMetricsEpsilon, err = parseutil.ParseDurationSecond(result.Telemetry.LeaseMetricsEpsilonRaw); err != nil {
				return err
			}
			result.Telemetry.LeaseMetricsEpsilonRaw = nil
		}
	} else {
		result.Telemetry.LeaseMetricsEpsilon = LeaseMetricsEpsilonDefault
	}

	if result.Telemetry.NumLeaseMetricsTimeBuckets == 0 {
		result.Telemetry.NumLeaseMetricsTimeBuckets = NumLeaseMetricsTimeBucketsDefault
	}

	return nil
}
