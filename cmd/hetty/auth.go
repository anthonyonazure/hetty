package main

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// authMiddleware gates a router behind a shared token. It accepts the token via
// HTTP Basic auth (any username, password == token — so browsers prompt and
// remember it), an "Authorization: Bearer <token>" header, or an
// "X-Hetty-Token" header (for API/CLI clients). Comparisons are constant-time.
func authMiddleware(token string) mux.MiddlewareFunc {
	want := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if authorized(r, want) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="hetty"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		})
	}
}

func authorized(r *http.Request, want []byte) bool {
	if _, pass, ok := r.BasicAuth(); ok && eq(pass, want) {
		return true
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if eq(strings.TrimPrefix(h, "Bearer "), want) {
			return true
		}
	}
	return eq(r.Header.Get("X-Hetty-Token"), want)
}

func eq(got string, want []byte) bool {
	return subtle.ConstantTimeCompare([]byte(got), want) == 1
}
