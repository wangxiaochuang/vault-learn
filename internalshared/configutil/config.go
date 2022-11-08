package configutil

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/token"
)

type SharedConfig struct {
	FoundKeys  []string     `hcl:",decodedFields"`
	UnusedKeys UnusedKeyMap `hcl:",unusedKeyPositions"`
	Sections   map[string][]token.Pos

	EntSharedConfig

	Listeners []*Listener `hcl:"-"`

	Seals   []*KMS   `hcl:"-"`
	Entropy *Entropy `hcl:"-"`

	DisableMlock    bool        `hcl:"-"`
	DisableMlockRaw interface{} `hcl:"disable_mlock"`

	Telemetry *Telemetry `hcl:"telemetry"`

	HCPLinkConf *HCPLinkConfig `hcl:"cloud"`

	DefaultMaxRequestDuration    time.Duration `hcl:"-"`
	DefaultMaxRequestDurationRaw interface{}   `hcl:"default_max_request_duration"`

	// LogFormat specifies the log format. Valid values are "standard" and
	// "json". The values are case-insenstive. If no log format is specified,
	// then standard format will be used.
	LogFormat string `hcl:"log_format"`
	LogLevel  string `hcl:"log_level"`

	PidFile string `hcl:"pid_file"`

	ClusterName string `hcl:"cluster_name"`
}

func LoadConfigFile(path string) (*SharedConfig, error) {
	// Read the file
	d, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(string(d))
}

func LoadConfigKMSes(path string) ([]*KMS, error) {
	// Read the file
	d, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKMSes(string(d))
}

func ParseConfig(d string) (*SharedConfig, error) {
	obj, err := hcl.Parse(d)
	if err != nil {
		return nil, err
	}

	// Start building the result
	var result SharedConfig

	if err := hcl.DecodeObject(&result, obj); err != nil {
		return nil, err
	}

	if result.DefaultMaxRequestDurationRaw != nil {
		if result.DefaultMaxRequestDuration, err = parseutil.ParseDurationSecond(result.DefaultMaxRequestDurationRaw); err != nil {
			return nil, err
		}
		result.FoundKeys = append(result.FoundKeys, "DefaultMaxRequestDuration")
		result.DefaultMaxRequestDurationRaw = nil
	}

	if result.DisableMlockRaw != nil {
		if result.DisableMlock, err = parseutil.ParseBool(result.DisableMlockRaw); err != nil {
			return nil, err
		}
		result.FoundKeys = append(result.FoundKeys, "DisableMlock")
		result.DisableMlockRaw = nil
	}

	list, ok := obj.Node.(*ast.ObjectList)
	if !ok {
		return nil, fmt.Errorf("error parsing: file doesn't contain a root object")
	}

	if o := list.Filter("hsm"); len(o.Items) > 0 {
		result.found("hsm", "hsm")
		if err := parseKMS(&result.Seals, o, "hsm", 2); err != nil {
			return nil, fmt.Errorf("error parsing 'hsm': %w", err)
		}
	}

	if o := list.Filter("seal"); len(o.Items) > 0 {
		result.found("seal", "Seal")
		if err := parseKMS(&result.Seals, o, "seal", 3); err != nil {
			return nil, fmt.Errorf("error parsing 'seal': %w", err)
		}
	}

	if o := list.Filter("kms"); len(o.Items) > 0 {
		result.found("kms", "Seal")
		if err := parseKMS(&result.Seals, o, "kms", 3); err != nil {
			return nil, fmt.Errorf("error parsing 'kms': %w", err)
		}
	}

	if o := list.Filter("entropy"); len(o.Items) > 0 {
		result.found("entropy", "Entropy")
		if err := ParseEntropy(&result, o, "entropy"); err != nil {
			return nil, fmt.Errorf("error parsing 'entropy': %w", err)
		}
	}

	if o := list.Filter("listener"); len(o.Items) > 0 {
		result.found("listener", "Listener")
		if err := ParseListeners(&result, o); err != nil {
			return nil, fmt.Errorf("error parsing 'listener': %w", err)
		}
	}

	if o := list.Filter("telemetry"); len(o.Items) > 0 {
		result.found("telemetry", "Telemetry")
		if err := parseTelemetry(&result, o); err != nil {
			return nil, fmt.Errorf("error parsing 'telemetry': %w", err)
		}
	}

	if o := list.Filter("cloud"); len(o.Items) > 0 {
		result.found("cloud", "Cloud")
		if err := parseCloud(&result, o); err != nil {
			return nil, fmt.Errorf("error parsing 'cloud': %w", err)
		}
	}

	entConfig := &(result.EntSharedConfig)
	if err := entConfig.ParseConfig(list); err != nil {
		return nil, fmt.Errorf("error parsing enterprise config: %w", err)
	}

	return &result, nil
}

// p249
func (c *SharedConfig) found(s, k string) {
	delete(c.UnusedKeys, s)
	c.FoundKeys = append(c.FoundKeys, k)
}
