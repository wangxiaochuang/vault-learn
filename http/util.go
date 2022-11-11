package http

import (
	"net"
	"net/http"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/hashicorp/vault/vault"
)

var (
	adjustRequest = func(c *vault.Core, r *http.Request) (*http.Request, int) {
		return r, 0
	}

	genericWrapping = func(core *vault.Core, in http.Handler, props *vault.HandlerProperties) http.Handler {
		// Wrap the help wrapped handler with another layer with a generic
		// handler
		return wrapGenericHandler(core, in, props)
	}

	additionalRoutes = func(mux *http.ServeMux, core *vault.Core) {}

	nonVotersAllowed = false

	adjustResponse = func(core *vault.Core, w http.ResponseWriter, req *logical.Request) {}
)

func rateLimitQuotaWrapping(handler http.Handler, core *vault.Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("not implement")
	})
}

func parseRemoteIPAddress(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}

	return ip
}
