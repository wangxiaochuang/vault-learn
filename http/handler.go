package http

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/hashicorp/vault/sdk/helper/pathmanager"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

const (
	// WrapTTLHeaderName is the name of the header containing a directive to
	// wrap the response
	WrapTTLHeaderName = "X-Vault-Wrap-TTL"

	// WrapFormatHeaderName is the name of the header containing the format to
	// wrap in; has no effect if the wrap TTL is not set
	WrapFormatHeaderName = "X-Vault-Wrap-Format"

	// NoRequestForwardingHeaderName is the name of the header telling Vault
	// not to use request forwarding
	NoRequestForwardingHeaderName = "X-Vault-No-Request-Forwarding"

	// MFAHeaderName represents the HTTP header which carries the credentials
	// required to perform MFA on any path.
	MFAHeaderName = "X-Vault-MFA"

	// canonicalMFAHeaderName is the MFA header value's format in the request
	// headers. Do not alter the casing of this string.
	canonicalMFAHeaderName = "X-Vault-Mfa"

	// PolicyOverrideHeaderName is the header set to request overriding
	// soft-mandatory Sentinel policies.
	PolicyOverrideHeaderName = "X-Vault-Policy-Override"

	VaultIndexHeaderName        = "X-Vault-Index"
	VaultInconsistentHeaderName = "X-Vault-Inconsistent"
	VaultForwardHeaderName      = "X-Vault-Forward"
	VaultInconsistentForward    = "forward-active-node"
	VaultInconsistentFail       = "fail"

	// DefaultMaxRequestSize is the default maximum accepted request size. This
	// is to prevent a denial of service attack where no Content-Length is
	// provided and the server is fed ever more data until it exhausts memory.
	// Can be overridden per listener.
	DefaultMaxRequestSize = 32 * 1024 * 1024
)

var (
	// Set to false by stub_asset if the ui build tag isn't enabled
	uiBuiltIn = true

	// perfStandbyAlwaysForwardPaths is used to check a requested path against
	// the always forward list
	perfStandbyAlwaysForwardPaths = pathmanager.New()
	alwaysRedirectPaths           = pathmanager.New()

	injectDataIntoTopRoutes = []string{
		"/v1/sys/audit",
		"/v1/sys/audit/",
		"/v1/sys/audit-hash/",
		"/v1/sys/auth",
		"/v1/sys/auth/",
		"/v1/sys/config/cors",
		"/v1/sys/config/auditing/request-headers/",
		"/v1/sys/config/auditing/request-headers",
		"/v1/sys/capabilities",
		"/v1/sys/capabilities-accessor",
		"/v1/sys/capabilities-self",
		"/v1/sys/ha-status",
		"/v1/sys/key-status",
		"/v1/sys/mounts",
		"/v1/sys/mounts/",
		"/v1/sys/policy",
		"/v1/sys/policy/",
		"/v1/sys/rekey/backup",
		"/v1/sys/rekey/recovery-key-backup",
		"/v1/sys/remount",
		"/v1/sys/rotate",
		"/v1/sys/wrapping/wrap",
	}

	oidcProtectedPathRegex = regexp.MustCompile(`^identity/oidc/provider/\w(([\w-.]+)?\w)?/userinfo$`)
)

func init() {
	alwaysRedirectPaths.AddPaths([]string{
		"sys/storage/raft/snapshot",
		"sys/storage/raft/snapshot-force",
		"!sys/storage/raft/snapshot-auto/config",
	})
}

// p123
func Handler(props *vault.HandlerProperties) http.Handler {
	core := props.Core
	mux := http.NewServeMux()
	switch {
	case props.RecoveryMode:
		panic("not implement")
	default:
		mux.Handle("/v1/sys/config/state/", handleLogicalNoForward(core))
		additionalRoutes(mux, core)
	}

	// Wrap the handler in another handler to trigger all help paths.
	helpWrappedHandler := wrapHelpHandler(mux, core)
	corsWrappedHandler := wrapCORSHandler(helpWrappedHandler, core)
	quotaWrappedHandler := rateLimitQuotaWrapping(corsWrappedHandler, core)
	genericWrappedHandler := genericWrapping(core, quotaWrappedHandler, props)

	// Wrap the handler with PrintablePathCheckHandler to check for non-printable
	// characters in the request path.
	printablePathCheckHandler := genericWrappedHandler
	if !props.DisablePrintableCheck {
		printablePathCheckHandler = cleanhttp.PrintablePathCheckHandler(genericWrappedHandler, nil)
	}

	return printablePathCheckHandler
}

// p294
func wrapGenericHandler(core *vault.Core, h http.Handler, props *vault.HandlerProperties) http.Handler {
	panic("not implement")
}

func WrapForwardedForHandler(h http.Handler, l *configutil.Listener) http.Handler {
	panic("not implement")
}

func stripPrefix(prefix, path string) (string, bool) {
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}

	path = path[len(prefix):]
	if path == "" {
		return "", false
	}

	return path, true
}

// p798
func handleRequestForwarding(core *vault.Core, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("not implement")
	})
}

// p1177
func respondError(w http.ResponseWriter, status int, err error) {
	logical.RespondError(w, status, err)
}

// p1200
func respondOk(w http.ResponseWriter, body interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if body == nil {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.Encode(body)
	}
}
