// Package collab implements a lightweight, HTTP-based out-of-band (OOB)
// interaction server — Hetty's analogue of Burp Collaborator. It issues unique
// tokens, embeds them in URLs handed to active scan payloads, and records any
// callback the target makes to that URL. This surfaces blind vulnerabilities
// (SSRF, blind command/template injection, XXE) that produce no in-band signal.
//
// Only the HTTP protocol is supported (no DNS), which covers the common case of
// a target that fetches an attacker-supplied URL.
package collab

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Interaction is a single recorded callback.
type Interaction struct {
	ID         string      `json:"id"`
	Token      string      `json:"token"`
	Protocol   string      `json:"protocol"`
	RemoteAddr string      `json:"remoteAddr"`
	Method     string      `json:"method"`
	Host       string      `json:"host"`
	Path       string      `json:"path"`
	Query      string      `json:"query"`
	UserAgent  string      `json:"userAgent"`
	Headers    http.Header `json:"headers"`
	Time       time.Time   `json:"time"`
}

// Server records OOB interactions keyed by token.
type Server struct {
	baseURL   string
	dnsDomain string

	mu           sync.Mutex
	interactions map[string][]Interaction
	known        map[string]struct{}
	seq          uint64
}

// NewServer returns a collaborator server. baseURL is the externally-reachable
// URL prefix the target can call back to (e.g. "http://10.0.0.5:8080/collab").
func NewServer(baseURL string) *Server {
	return &Server{
		baseURL:      strings.TrimRight(baseURL, "/"),
		interactions: make(map[string][]Interaction),
		known:        make(map[string]struct{}),
	}
}

// BaseURL returns the configured callback URL prefix.
func (s *Server) BaseURL() string { return s.baseURL }

// SetBaseURL updates the callback URL prefix (used once the listen address is
// known).
func (s *Server) SetBaseURL(u string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseURL = strings.TrimRight(u, "/")
}

// NewToken issues a unique token and the full callback URL to embed in a
// payload.
func (s *Server) NewToken() (token, url string) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a sequence-based token; uniqueness still holds.
		s.mu.Lock()
		s.seq++
		token = "seq" + hex.EncodeToString([]byte{byte(s.seq), byte(s.seq >> 8)})
		s.mu.Unlock()
	} else {
		token = hex.EncodeToString(b)
	}

	s.mu.Lock()
	s.known[token] = struct{}{}
	if _, ok := s.interactions[token]; !ok {
		s.interactions[token] = nil
	}
	s.mu.Unlock()

	return token, s.baseURL + "/" + token
}

// Interactions returns the recorded interactions for a token (newest last).
func (s *Server) Interactions(token string) []Interaction {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Interaction, len(s.interactions[token]))
	copy(out, s.interactions[token])

	return out
}

// InteractionCount returns the number of interactions recorded for a token.
func (s *Server) InteractionCount(token string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.interactions[token])
}

// Handler returns an http.Handler that records interactions. It expects to be
// mounted such that the first path segment is the token (e.g. behind
// http.StripPrefix("/collab", ...)).
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := firstSegment(r.URL.Path)
		if token != "" {
			s.record(token, r)
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func (s *Server) record(token string, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	interaction := Interaction{
		ID:         hex.EncodeToString([]byte{byte(s.seq), byte(s.seq >> 8), byte(s.seq >> 16)}),
		Token:      token,
		Protocol:   "http",
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Host:       r.Host,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		UserAgent:  r.UserAgent(),
		Headers:    r.Header.Clone(),
		Time:       time.Now().UTC(),
	}

	s.interactions[token] = append(s.interactions[token], interaction)
}

func firstSegment(path string) string {
	path = strings.TrimLeft(path, "/")
	if path == "" {
		return ""
	}
	if idx := strings.IndexByte(path, '/'); idx >= 0 {
		return path[:idx]
	}

	return path
}
