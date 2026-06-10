package scan

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// randToken returns a random lowercase hex token of n bytes (2n chars).
func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// rand.Read only fails in catastrophic conditions; fall back to a
		// fixed but still distinctive marker.
		return "hettyfallback"
	}

	return hex.EncodeToString(b)
}

// isHTMLResponse reports whether a response looks like HTML based on its
// Content-Type.
func isHTMLResponse(res *Response) bool {
	if res == nil {
		return false
	}

	ct := strings.ToLower(res.Header.Get("Content-Type"))

	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

// snippet returns up to maxLen characters of s surrounding the first
// occurrence of marker, for use as evidence.
func snippet(s, marker string, maxLen int) string {
	idx := strings.Index(s, marker)
	if idx == -1 {
		if len(s) > maxLen {
			return s[:maxLen]
		}
		return s
	}

	start := idx - maxLen/2
	if start < 0 {
		start = 0
	}

	end := idx + len(marker) + maxLen/2
	if end > len(s) {
		end = len(s)
	}

	out := s[start:end]
	if start > 0 {
		out = "…" + out
	}
	if end < len(s) {
		out += "…"
	}

	return out
}

// headerLocationHost returns the host of a response's Location header.
func headerLocationHost(res *Response) string {
	loc := res.Header.Get("Location")
	if loc == "" {
		return ""
	}

	return loc
}

// cloneHeader is a small helper used by tests and checks.
func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return make(http.Header)
	}

	return h.Clone()
}
