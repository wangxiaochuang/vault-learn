package http

import (
	"net/http"

	"github.com/hashicorp/vault/vault"
)

// p307
func handleLogicalNoForward(core *vault.Core) http.Handler {
	return handleLogicalInternal(core, false, true)
}

// p341
func handleLogicalInternal(core *vault.Core, injectDataIntoTopLevel bool, noForward bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("not implement")
	})
}
