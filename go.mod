module github.com/hashicorp/vault

go 1.19

replace github.com/hashicorp/vault/sdk => ./sdk

require (
	cloud.google.com/go/monitoring v1.5.0
	github.com/armon/go-metrics v0.4.1
	github.com/armon/go-radix v1.0.0
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d
	github.com/fatih/color v1.13.0
	github.com/golang/protobuf v1.5.2
	github.com/google/go-metrics-stackdriver v0.5.0
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.3.1
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.5
	github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2 v2.0.4
	github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2 v2.0.1
	github.com/hashicorp/go-memdb v1.3.4
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-plugin v1.4.6
	github.com/hashicorp/go-retryablehttp v0.7.1
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-secure-stdlib/gatedwriter v0.1.1
	github.com/hashicorp/go-secure-stdlib/mlock v0.1.2
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7
	github.com/hashicorp/go-secure-stdlib/reloadutil v0.1.1
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2
	github.com/hashicorp/go-secure-stdlib/tlsutil v0.1.2
	github.com/hashicorp/go-sockaddr v1.0.2
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/golang-lru v0.5.4
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault-plugin-secrets-kv v0.13.3
	github.com/hashicorp/vault/sdk v0.6.0
	github.com/jefferai/isbadcipher v0.0.0-20190226160619-51d2077c035f
	github.com/kr/pretty v0.3.1
	github.com/kr/text v0.2.0
	github.com/mattn/go-colorable v0.1.12
	github.com/mitchellh/cli v1.1.4
	github.com/mitchellh/copystructure v1.0.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pires/go-proxyproto v0.6.2
	github.com/posener/complete v1.1.1
	go.uber.org/atomic v1.10.0
	golang.org/x/crypto v0.0.0-20220313003712-b769efc7c000
	golang.org/x/net v0.1.0
	golang.org/x/time v0.2.0
	google.golang.org/api v0.79.0
	google.golang.org/grpc v1.50.1
	google.golang.org/protobuf v1.28.1
)

require (
	cloud.google.com/go/compute v1.6.1 // indirect
	github.com/DataDog/datadog-go v3.2.0+incompatible // indirect
	github.com/Masterminds/goutils v1.1.0 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.0 // indirect
	github.com/aws/aws-sdk-go v1.43.8 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bgentry/speakeasy v0.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/circonus-labs/circonus-gometrics v2.3.1+incompatible // indirect
	github.com/circonus-labs/circonusllhist v0.1.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/evanphx/json-patch/v5 v5.5.0 // indirect
	github.com/frankban/quicktest v1.14.3 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/google/uuid v1.1.2 // indirect
	github.com/googleapis/gax-go/v2 v2.3.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-kms-wrapping/entropy/v2 v2.0.0 // indirect
	github.com/hashicorp/go-secure-stdlib/awsutil v0.1.6 // indirect
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-testing-interface v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.0 // indirect
	github.com/oklog/run v1.0.0 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.4.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.9.1 // indirect
	github.com/prometheus/procfs v0.0.8 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/stretchr/testify v1.7.2 // indirect
	github.com/tv42/httpunix v0.0.0-20150427012821-b75d8614f926 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/oauth2 v0.0.0-20220411215720-9780585627b5 // indirect
	golang.org/x/sys v0.1.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220505152158-f39f71e6c8f3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
