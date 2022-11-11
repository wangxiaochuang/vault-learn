package http

import (
	"net/http"

	"github.com/hashicorp/vault/vault"
)

func wrapHelpHandler(h http.Handler, core *vault.Core) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		// If the help parameter is not blank, then show the help. We request
		// forward because standby nodes do not have mounts and other state.
		if v := req.URL.Query().Get("help"); v != "" || req.Method == "HELP" {
			handleRequestForwarding(core,
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					handleHelp(core, w, r)
				})).ServeHTTP(writer, req)
			return
		}

		h.ServeHTTP(writer, req)
		return
	})
}

func handleHelp(core *vault.Core, w http.ResponseWriter, r *http.Request) {
	panic("not implement")
}
