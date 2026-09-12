// Package router builds this service's complete HTTP handler. It's the
// package dash-xd/gospace-minimal's deploy tooling drops an import of
// into internal/routersource/source/source.go to serve this repo as a
// GCP Cloud Function - the same contract every service deployed through
// that shell satisfies (see .github/actions/deploy-token-minter, which
// wires this in).
package router

import (
	"net/http"

	"github.com/xd-dash/atman/internal/handler"
)

// NewRouter returns the token-minter's http.Handler.
func NewRouter() http.Handler {
	return handler.New()
}
