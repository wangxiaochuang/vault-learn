package api

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/go-rootcerts"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

const (
	EnvVaultAddress          = "VAULT_ADDR"
	EnvVaultAgentAddr        = "VAULT_AGENT_ADDR"
	EnvVaultCACert           = "VAULT_CACERT"
	EnvVaultCACertBytes      = "VAULT_CACERT_BYTES"
	EnvVaultCAPath           = "VAULT_CAPATH"
	EnvVaultClientCert       = "VAULT_CLIENT_CERT"
	EnvVaultClientKey        = "VAULT_CLIENT_KEY"
	EnvVaultClientTimeout    = "VAULT_CLIENT_TIMEOUT"
	EnvVaultSRVLookup        = "VAULT_SRV_LOOKUP"
	EnvVaultSkipVerify       = "VAULT_SKIP_VERIFY"
	EnvVaultNamespace        = "VAULT_NAMESPACE"
	EnvVaultTLSServerName    = "VAULT_TLS_SERVER_NAME"
	EnvVaultWrapTTL          = "VAULT_WRAP_TTL"
	EnvVaultMaxRetries       = "VAULT_MAX_RETRIES"
	EnvVaultToken            = "VAULT_TOKEN"
	EnvVaultMFA              = "VAULT_MFA"
	EnvRateLimit             = "VAULT_RATE_LIMIT"
	EnvHTTPProxy             = "VAULT_HTTP_PROXY"
	EnvVaultProxyAddr        = "VAULT_PROXY_ADDR"
	EnvVaultDisableRedirects = "VAULT_DISABLE_REDIRECTS"
	HeaderIndex              = "X-Vault-Index"
	HeaderForward            = "X-Vault-Forward"
	HeaderInconsistent       = "X-Vault-Inconsistent"
	TLSErrorString           = "This error usually means that the server is running with TLS disabled\n" +
		"but the client is configured to use TLS. Please either enable TLS\n" +
		"on the server or run the client with -address set to an address\n" +
		"that uses the http protocol:\n\n" +
		"    vault <command> -address http://<address>\n\n" +
		"You can also set the VAULT_ADDR environment variable:\n\n\n" +
		"    VAULT_ADDR=http://<address> vault <command>\n\n" +
		"where <address> is replaced by the actual address to the server."
)

// Deprecated values
const (
	EnvVaultAgentAddress = "VAULT_AGENT_ADDR"
	EnvVaultInsecure     = "VAULT_SKIP_VERIFY"
)

type WrappingLookupFunc func(operation, path string) string

// 84
type Config struct {
	modifyLock                    sync.RWMutex
	Address                       string
	AgentAddress                  string
	HttpClient                    *http.Client
	MinRetryWait                  time.Duration
	MaxRetryWait                  time.Duration
	MaxRetries                    int
	Timeout                       time.Duration
	Error                         error
	Backoff                       retryablehttp.Backoff
	CheckRetry                    retryablehttp.CheckRetry
	Logger                        retryablehttp.LeveledLogger
	Limiter                       *rate.Limiter
	OutputCurlString              bool
	OutputPolicy                  bool
	curlCACert, curlCAPath        string
	curlClientCert, curlClientKey string
	SRVLookup                     bool
	CloneHeaders                  bool
	CloneToken                    bool
	ReadYourWrites                bool
	DisableRedirects              bool
}

// p194
type TLSConfig struct {
	// CACert is the path to a PEM-encoded CA cert file to use to verify the
	// Vault server SSL certificate. It takes precedence over CACertBytes
	// and CAPath.
	CACert string

	// CACertBytes is a PEM-encoded certificate or bundle. It takes precedence
	// over CAPath.
	CACertBytes []byte

	// CAPath is the path to a directory of PEM-encoded CA cert files to verify
	// the Vault server SSL certificate.
	CAPath string

	// ClientCert is the path to the certificate for Vault communication
	ClientCert string

	// ClientKey is the path to the private key for Vault communication
	ClientKey string

	// TLSServerName, if set, is used to set the SNI host when connecting via
	// TLS.
	TLSServerName string

	// Insecure enables or disables SSL verification
	Insecure bool
}

func DefaultConfig() *Config {
	config := &Config{
		Address:      "https://127.0.0.1:8200",
		HttpClient:   cleanhttp.DefaultPooledClient(),
		Timeout:      time.Second * 60,
		MinRetryWait: time.Millisecond * 1000,
		MaxRetryWait: time.Millisecond * 1500,
		MaxRetries:   2,
		Backoff:      retryablehttp.LinearJitterBackoff,
	}

	transport := config.HttpClient.Transport.(*http.Transport)
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		config.Error = err
		return config
	}

	if err := config.ReadEnvironment(); err != nil {
		config.Error = err
		return config
	}

	// Ensure redirects are not automatically followed
	// Note that this is sane for the API client as it has its own
	// redirect handling logic (and thus also for command/meta),
	// but in e.g. http_test actual redirect handling is necessary
	config.HttpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Returning this value causes the Go net library to not close the
		// response body and to nil out the error. Otherwise retry clients may
		// try three times on every redirect because it sees an error from this
		// function (to prevent redirects) passing through to it.
		return http.ErrUseLastResponse
	}

	return config
}

func (c *Config) configureTLS(t *TLSConfig) error {
	if c.HttpClient == nil {
		c.HttpClient = DefaultConfig().HttpClient
	}
	clientTLSConfig := c.HttpClient.Transport.(*http.Transport).TLSClientConfig

	var clientCert tls.Certificate
	foundClientCert := false

	switch {
	case t.ClientCert != "" && t.ClientKey != "":
		var err error
		clientCert, err = tls.LoadX509KeyPair(t.ClientCert, t.ClientKey)
		if err != nil {
			return err
		}
		foundClientCert = true
		c.curlClientCert = t.ClientCert
		c.curlClientKey = t.ClientKey
	case t.ClientCert != "" || t.ClientKey != "":
		return fmt.Errorf("both client cert and client key must be provided")
	}

	if t.CACert != "" || len(t.CACertBytes) != 0 || t.CAPath != "" {
		c.curlCACert = t.CACert
		c.curlCAPath = t.CAPath
		rootConfig := &rootcerts.Config{
			CAFile:        t.CACert,
			CACertificate: t.CACertBytes,
			CAPath:        t.CAPath,
		}
		if err := rootcerts.ConfigureTLS(clientTLSConfig, rootConfig); err != nil {
			return err
		}
	}

	if t.Insecure {
		clientTLSConfig.InsecureSkipVerify = true
	}

	if foundClientCert {
		// We use this function to ignore the server's preferential list of
		// CAs, otherwise any CA used for the cert auth backend must be in the
		// server's CA pool
		clientTLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}

	if t.TLSServerName != "" {
		clientTLSConfig.ServerName = t.TLSServerName
	}

	return nil
}

// ConfigureTLS takes a set of TLS configurations and applies those to the
// HTTP client.
func (c *Config) ConfigureTLS(t *TLSConfig) error {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	return c.configureTLS(t)
}

// ReadEnvironment reads configuration information from the environment. If
// there is an error, no configuration value is updated.
func (c *Config) ReadEnvironment() error {
	var envAddress string
	var envAgentAddress string
	var envCACert string
	var envCACertBytes []byte
	var envCAPath string
	var envClientCert string
	var envClientKey string
	var envClientTimeout time.Duration
	var envInsecure bool
	var envTLSServerName string
	var envMaxRetries *uint64
	var envSRVLookup bool
	var limit *rate.Limiter
	var envVaultProxy string
	var envVaultDisableRedirects bool

	// Parse the environment variables
	if v := os.Getenv(EnvVaultAddress); v != "" {
		envAddress = v
	}
	if v := os.Getenv(EnvVaultAgentAddr); v != "" {
		envAgentAddress = v
	}
	if v := os.Getenv(EnvVaultMaxRetries); v != "" {
		maxRetries, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return err
		}
		envMaxRetries = &maxRetries
	}
	if v := os.Getenv(EnvVaultCACert); v != "" {
		envCACert = v
	}
	if v := os.Getenv(EnvVaultCACertBytes); v != "" {
		envCACertBytes = []byte(v)
	}
	if v := os.Getenv(EnvVaultCAPath); v != "" {
		envCAPath = v
	}
	if v := os.Getenv(EnvVaultClientCert); v != "" {
		envClientCert = v
	}
	if v := os.Getenv(EnvVaultClientKey); v != "" {
		envClientKey = v
	}
	if v := os.Getenv(EnvRateLimit); v != "" {
		rateLimit, burstLimit, err := parseRateLimit(v)
		if err != nil {
			return err
		}
		limit = rate.NewLimiter(rate.Limit(rateLimit), burstLimit)
	}
	if t := os.Getenv(EnvVaultClientTimeout); t != "" {
		clientTimeout, err := parseutil.ParseDurationSecond(t)
		if err != nil {
			return fmt.Errorf("could not parse %q", EnvVaultClientTimeout)
		}
		envClientTimeout = clientTimeout
	}
	if v := os.Getenv(EnvVaultSkipVerify); v != "" {
		var err error
		envInsecure, err = strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("could not parse %s", EnvVaultSkipVerify)
		}
	}
	if v := os.Getenv(EnvVaultSRVLookup); v != "" {
		var err error
		envSRVLookup, err = strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("could not parse %s", EnvVaultSRVLookup)
		}
	}

	if v := os.Getenv(EnvVaultTLSServerName); v != "" {
		envTLSServerName = v
	}

	if v := os.Getenv(EnvHTTPProxy); v != "" {
		envVaultProxy = v
	}

	// VAULT_PROXY_ADDR supersedes VAULT_HTTP_PROXY
	if v := os.Getenv(EnvVaultProxyAddr); v != "" {
		envVaultProxy = v
	}

	if v := os.Getenv(EnvVaultDisableRedirects); v != "" {
		var err error
		envVaultDisableRedirects, err = strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("could not parse %s", EnvVaultDisableRedirects)
		}

		c.DisableRedirects = envVaultDisableRedirects
	}

	// Configure the HTTP clients TLS configuration.
	t := &TLSConfig{
		CACert:        envCACert,
		CACertBytes:   envCACertBytes,
		CAPath:        envCAPath,
		ClientCert:    envClientCert,
		ClientKey:     envClientKey,
		TLSServerName: envTLSServerName,
		Insecure:      envInsecure,
	}

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.SRVLookup = envSRVLookup
	c.Limiter = limit

	if err := c.configureTLS(t); err != nil {
		return err
	}

	if envAddress != "" {
		c.Address = envAddress
	}

	if envAgentAddress != "" {
		c.AgentAddress = envAgentAddress
	}

	if envMaxRetries != nil {
		c.MaxRetries = int(*envMaxRetries)
	}

	if envClientTimeout != 0 {
		c.Timeout = envClientTimeout
	}

	if envVaultProxy != "" {
		u, err := url.Parse(envVaultProxy)
		if err != nil {
			return err
		}

		transport := c.HttpClient.Transport.(*http.Transport)
		transport.Proxy = http.ProxyURL(u)
	}

	return nil
}

// p532
func parseRateLimit(val string) (rate float64, burst int, err error) {
	_, err = fmt.Sscanf(val, "%f:%d", &rate, &burst)
	if err != nil {
		rate, err = strconv.ParseFloat(val, 64)
		if err != nil {
			err = fmt.Errorf("%v was provided but incorrectly formatted", EnvRateLimit)
		}
		burst = int(rate)
	}

	return rate, burst, err
}

// p546
type Client struct {
	modifyLock            sync.RWMutex
	addr                  *url.URL
	config                *Config
	token                 string
	headers               http.Header
	wrappingLookupFunc    WrappingLookupFunc
	mfaCreds              []string
	policyOverride        bool
	requestCallbacks      []RequestCallback
	responseCallbacks     []ResponseCallback
	replicationStateStore *replicationStateStore
}

// p1557
type (
	RequestCallback  func(*Request)
	ResponseCallback func(*Response)
)

// p1752
type replicationStateStore struct {
	m     sync.RWMutex
	store []string
}
