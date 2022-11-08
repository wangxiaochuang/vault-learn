package api

import (
	"context"
	"crypto/tls"
	"flag"
	"regexp"
)

const (
	// PluginAutoMTLSEnv is used to ensure AutoMTLS is used. This will override
	// setting a TLSProviderFunc for a plugin.
	PluginAutoMTLSEnv = "VAULT_PLUGIN_AUTOMTLS_ENABLED"

	// PluginMetadataModeEnv is an ENV name used to disable TLS communication
	// to bootstrap mounting plugins.
	PluginMetadataModeEnv = "VAULT_PLUGIN_METADATA_MODE"

	// PluginUnwrapTokenEnv is the ENV name used to pass unwrap tokens to the
	// plugin.
	PluginUnwrapTokenEnv = "VAULT_UNWRAP_TOKEN"
)

// sudoPaths is a map containing the paths that require a token's policy
// to have the "sudo" capability. The keys are the paths as strings, in
// the same format as they are returned by the OpenAPI spec. The values
// are the regular expressions that can be used to test whether a given
// path matches that path or not (useful specifically for the paths that
// contain templated fields.)
var sudoPaths = map[string]*regexp.Regexp{
	"/auth/token/accessors/":                        regexp.MustCompile(`^/auth/token/accessors/$`),
	"/pki/root":                                     regexp.MustCompile(`^/pki/root$`),
	"/pki/root/sign-self-issued":                    regexp.MustCompile(`^/pki/root/sign-self-issued$`),
	"/sys/audit":                                    regexp.MustCompile(`^/sys/audit$`),
	"/sys/audit/{path}":                             regexp.MustCompile(`^/sys/audit/.+$`),
	"/sys/auth/{path}":                              regexp.MustCompile(`^/sys/auth/.+$`),
	"/sys/auth/{path}/tune":                         regexp.MustCompile(`^/sys/auth/.+/tune$`),
	"/sys/config/auditing/request-headers":          regexp.MustCompile(`^/sys/config/auditing/request-headers$`),
	"/sys/config/auditing/request-headers/{header}": regexp.MustCompile(`^/sys/config/auditing/request-headers/.+$`),
	"/sys/config/cors":                              regexp.MustCompile(`^/sys/config/cors$`),
	"/sys/config/ui/headers/":                       regexp.MustCompile(`^/sys/config/ui/headers/$`),
	"/sys/config/ui/headers/{header}":               regexp.MustCompile(`^/sys/config/ui/headers/.+$`),
	"/sys/leases":                                   regexp.MustCompile(`^/sys/leases$`),
	"/sys/leases/lookup/":                           regexp.MustCompile(`^/sys/leases/lookup/$`),
	"/sys/leases/lookup/{prefix}":                   regexp.MustCompile(`^/sys/leases/lookup/.+$`),
	"/sys/leases/revoke-force/{prefix}":             regexp.MustCompile(`^/sys/leases/revoke-force/.+$`),
	"/sys/leases/revoke-prefix/{prefix}":            regexp.MustCompile(`^/sys/leases/revoke-prefix/.+$`),
	"/sys/plugins/catalog/{name}":                   regexp.MustCompile(`^/sys/plugins/catalog/[^/]+$`),
	"/sys/plugins/catalog/{type}":                   regexp.MustCompile(`^/sys/plugins/catalog/[\w-]+$`),
	"/sys/plugins/catalog/{type}/{name}":            regexp.MustCompile(`^/sys/plugins/catalog/[\w-]+/[^/]+$`),
	"/sys/raw":                                      regexp.MustCompile(`^/sys/raw$`),
	"/sys/raw/{path}":                               regexp.MustCompile(`^/sys/raw/.+$`),
	"/sys/remount":                                  regexp.MustCompile(`^/sys/remount$`),
	"/sys/revoke-force/{prefix}":                    regexp.MustCompile(`^/sys/revoke-force/.+$`),
	"/sys/revoke-prefix/{prefix}":                   regexp.MustCompile(`^/sys/revoke-prefix/.+$`),
	"/sys/rotate":                                   regexp.MustCompile(`^/sys/rotate$`),

	// enterprise-only paths
	"/sys/replication/dr/primary/secondary-token":          regexp.MustCompile(`^/sys/replication/dr/primary/secondary-token$`),
	"/sys/replication/performance/primary/secondary-token": regexp.MustCompile(`^/sys/replication/performance/primary/secondary-token$`),
	"/sys/replication/primary/secondary-token":             regexp.MustCompile(`^/sys/replication/primary/secondary-token$`),
	"/sys/replication/reindex":                             regexp.MustCompile(`^/sys/replication/reindex$`),
	"/sys/storage/raft/snapshot-auto/config/":              regexp.MustCompile(`^/sys/storage/raft/snapshot-auto/config/$`),
	"/sys/storage/raft/snapshot-auto/config/{name}":        regexp.MustCompile(`^/sys/storage/raft/snapshot-auto/config/[^/]+$`),
}

// PluginAPIClientMeta is a helper that plugins can use to configure TLS connections
// back to Vault.
type PluginAPIClientMeta struct {
	// These are set by the command line flags.
	flagCACert     string
	flagCAPath     string
	flagClientCert string
	flagClientKey  string
	flagInsecure   bool
}

// FlagSet returns the flag set for configuring the TLS connection
func (f *PluginAPIClientMeta) FlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("vault plugin settings", flag.ContinueOnError)

	fs.StringVar(&f.flagCACert, "ca-cert", "", "")
	fs.StringVar(&f.flagCAPath, "ca-path", "", "")
	fs.StringVar(&f.flagClientCert, "client-cert", "", "")
	fs.StringVar(&f.flagClientKey, "client-key", "", "")
	fs.BoolVar(&f.flagInsecure, "tls-skip-verify", false, "")

	return fs
}

// GetTLSConfig will return a TLSConfig based off the values from the flags
func (f *PluginAPIClientMeta) GetTLSConfig() *TLSConfig {
	// If we need custom TLS configuration, then set it
	if f.flagCACert != "" || f.flagCAPath != "" || f.flagClientCert != "" || f.flagClientKey != "" || f.flagInsecure {
		t := &TLSConfig{
			CACert:        f.flagCACert,
			CAPath:        f.flagCAPath,
			ClientCert:    f.flagClientCert,
			ClientKey:     f.flagClientKey,
			TLSServerName: "",
			Insecure:      f.flagInsecure,
		}

		return t
	}

	return nil
}

// VaultPluginTLSProvider wraps VaultPluginTLSProviderContext using context.Background.
func VaultPluginTLSProvider(apiTLSConfig *TLSConfig) func() (*tls.Config, error) {
	return VaultPluginTLSProviderContext(context.Background(), apiTLSConfig)
}

// VaultPluginTLSProviderContext is run inside a plugin and retrieves the response
// wrapped TLS certificate from vault. It returns a configured TLS Config.
func VaultPluginTLSProviderContext(ctx context.Context, apiTLSConfig *TLSConfig) func() (*tls.Config, error) {
	panic("not implement")
}

func SudoPaths() map[string]*regexp.Regexp {
	return sudoPaths
}

// Determine whether the given path requires the sudo capability
func IsSudoPath(path string) bool {
	// Return early if the path is any of the non-templated sudo paths.
	if _, ok := sudoPaths[path]; ok {
		return true
	}

	// Some sudo paths have templated fields in them.
	// (e.g. /sys/revoke-prefix/{prefix})
	// The values in the sudoPaths map are actually regular expressions,
	// so we can check if our path matches against them.
	for _, sudoPathRegexp := range sudoPaths {
		match := sudoPathRegexp.MatchString(path)
		if match {
			return true
		}
	}

	return false
}
