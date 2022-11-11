package configutil

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

var (
	ConfigureWrapper             = configureWrapper
	CreateSecureRandomReaderFunc = createSecureRandomReader
)

type EntropyMode int

const (
	EntropyUnknown EntropyMode = iota
	EntropyAugmentation
)

type Entropy struct {
	Mode EntropyMode
}

// p45
type KMS struct {
	UnusedKeys []string `hcl:",unusedKeys"`
	Type       string
	Purpose    []string `hcl:"-"`

	Disabled bool
	Config   map[string]string
}

func (k *KMS) GoString() string {
	return fmt.Sprintf("*%#v", *k)
}

func parseKMS(result *[]*KMS, list *ast.ObjectList, blockName string, maxKMS int) error {
	if len(list.Items) > maxKMS {
		return fmt.Errorf("only two or less %q blocks are permitted", blockName)
	}

	seals := make([]*KMS, 0, len(list.Items))
	for _, item := range list.Items {
		key := blockName
		if len(item.Keys) > 0 {
			key = item.Keys[0].Token.Value().(string)
		}

		// We first decode into a map[string]interface{} because purpose isn't
		// necessarily a string. Then we migrate everything else over to
		// map[string]string and error if it doesn't work.
		var m map[string]interface{}
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
		}

		var purpose []string
		var err error
		if v, ok := m["purpose"]; ok {
			if purpose, err = parseutil.ParseCommaStringSlice(v); err != nil {
				return multierror.Prefix(fmt.Errorf("unable to parse 'purpose' in kms type %q: %w", key, err), fmt.Sprintf("%s.%s:", blockName, key))
			}
			for i, p := range purpose {
				purpose[i] = strings.ToLower(p)
			}
			delete(m, "purpose")
		}

		var disabled bool
		if v, ok := m["disabled"]; ok {
			disabled, err = parseutil.ParseBool(v)
			if err != nil {
				return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
			}
			delete(m, "disabled")
		}

		strMap := make(map[string]string, len(m))
		for k, v := range m {
			s, err := parseutil.ParseString(v)
			if err != nil {
				return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
			}
			strMap[k] = s
		}

		seal := &KMS{
			Type:     strings.ToLower(key),
			Purpose:  purpose,
			Disabled: disabled,
		}
		if len(strMap) > 0 {
			seal.Config = strMap
		}
		seals = append(seals, seal)
	}

	*result = append(*result, seals...)

	return nil
}

// p127
func ParseKMSes(d string) ([]*KMS, error) {
	panic("not implement")
}

// p163
func configureWrapper(configKMS *KMS, infoKeys *[]string, info *map[string]string, logger hclog.Logger, opts ...wrapping.Option) (wrapping.Wrapper, error) {
	switch wrapping.WrapperType(configKMS.Type) {
	case wrapping.WrapperTypeShamir:
		return nil, nil
	default:
		panic("not implement")
	}
}

// p345
func createSecureRandomReader(conf *SharedConfig, wrapper wrapping.Wrapper) (io.Reader, error) {
	return rand.Reader, nil
}
