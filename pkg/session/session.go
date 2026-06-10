// Package session implements authentication profiles and session handling for
// Hetty — the analogue of Burp's session-handling rules and cookie jar. A
// Profile is a named identity (a set of headers and cookies, optionally a
// bearer token) that other tools (sender, scanner, intruder, authz) can apply
// to outgoing requests so they run as a specific authenticated user.
//
// A Profile may also carry a CSRFRule: before a state-changing request, Hetty
// fetches a page, extracts an anti-CSRF token with a regular expression, and
// injects it into a header or body parameter. This keeps automated requests
// valid against apps that enforce per-request CSRF tokens.
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// Header is a single header injected by a profile.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Cookie is a single cookie injected by a profile.
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CSRFRule describes how to obtain and inject an anti-CSRF token.
type CSRFRule struct {
	// FetchURL is GET'd to obtain a page containing the token.
	FetchURL string `json:"fetchUrl"`
	// Pattern is a regular expression with exactly one capture group that
	// isolates the token from the fetched body.
	Pattern string `json:"pattern"`
	// InjectHeader, when set, is the header the resolved token is written to.
	InjectHeader string `json:"injectHeader"`
	// InjectParam, when set, is the form/query parameter the token is written
	// to (handled by callers that build the request body).
	InjectParam string `json:"injectParam"`

	re *regexp.Regexp
}

func (r *CSRFRule) compile() error {
	if r.Pattern == "" {
		return fmt.Errorf("session: CSRF rule needs a pattern")
	}
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return fmt.Errorf("session: invalid CSRF pattern: %w", err)
	}
	if re.NumSubexp() != 1 {
		return fmt.Errorf("session: CSRF pattern must have exactly one capture group")
	}
	r.re = re
	return nil
}

// Resolve fetches FetchURL and extracts the token. The supplied client carries
// the identity's cookies/headers if the caller applied them first.
func (r *CSRFRule) Resolve(ctx context.Context, client *http.Client) (string, error) {
	if r.re == nil {
		if err := r.compile(); err != nil {
			return "", err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.FetchURL, nil)
	if err != nil {
		return "", fmt.Errorf("session: build CSRF fetch request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("session: CSRF fetch failed: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("session: read CSRF response: %w", err)
	}

	m := r.re.FindSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("session: CSRF token not found at %s", r.FetchURL)
	}

	return string(m[1]), nil
}

// Profile is a named authentication identity.
type Profile struct {
	Name    string   `json:"name"`
	Headers []Header `json:"headers"`
	Cookies []Cookie `json:"cookies"`
	// Bearer, when set, is added as an "Authorization: Bearer <token>" header.
	Bearer string    `json:"bearer"`
	CSRF   *CSRFRule `json:"csrf,omitempty"`
}

// Apply injects the profile's headers, bearer token and cookies into h. It
// merges with any existing Cookie header rather than clobbering it.
func (p Profile) Apply(h http.Header) {
	if h == nil {
		return
	}

	for _, hdr := range p.Headers {
		if hdr.Name != "" {
			h.Set(hdr.Name, hdr.Value)
		}
	}

	if p.Bearer != "" {
		h.Set("Authorization", "Bearer "+p.Bearer)
	}

	if len(p.Cookies) > 0 {
		var parts []string
		if existing := h.Get("Cookie"); existing != "" {
			parts = append(parts, existing)
		}
		for _, c := range p.Cookies {
			if c.Name != "" {
				parts = append(parts, c.Name+"="+c.Value)
			}
		}
		h.Set("Cookie", strings.Join(parts, "; "))
	}
}

// Inject applies the profile to h and, when the profile carries a CSRF rule
// with an inject header, resolves a fresh token (using client) and sets it. A
// CSRF resolution failure is non-fatal: the static headers/cookies are still
// applied. Pass a nil client to skip CSRF resolution.
func (p Profile) Inject(ctx context.Context, client *http.Client, h http.Header) {
	p.Apply(h)

	if p.CSRF != nil && p.CSRF.InjectHeader != "" && client != nil {
		if tok, err := p.CSRF.Resolve(ctx, client); err == nil {
			h.Set(p.CSRF.InjectHeader, tok)
		}
	}
}

// Stripped returns a copy of h with all identity-bearing headers removed,
// representing an unauthenticated request.
func Stripped(h http.Header) http.Header {
	out := h.Clone()
	if out == nil {
		out = make(http.Header)
	}
	out.Del("Authorization")
	out.Del("Cookie")
	out.Del("X-Api-Key")
	out.Del("X-Auth-Token")
	return out
}

// Store is an in-memory set of named profiles.
type Store struct {
	mu       sync.RWMutex
	profiles map[string]Profile
}

// NewStore returns an empty profile store.
func NewStore() *Store {
	return &Store{profiles: make(map[string]Profile)}
}

// Set adds or replaces a profile. It validates a CSRF rule if present.
func (s *Store) Set(p Profile) error {
	if p.Name == "" {
		return fmt.Errorf("session: profile name required")
	}
	if p.CSRF != nil {
		if err := p.CSRF.compile(); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.profiles[p.Name] = p
	return nil
}

// Get returns a profile by name.
func (s *Store) Get(name string) (Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[name]
	return p, ok
}

// List returns all profiles.
func (s *Store) List() []Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Profile, 0, len(s.profiles))
	for _, p := range s.profiles {
		out = append(out, p)
	}
	return out
}

// Delete removes a profile.
func (s *Store) Delete(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.profiles, name)
}

// Snapshot serializes the store for persistence.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.profiles)
}

// Restore loads profiles from a snapshot, recompiling CSRF rules.
func (s *Store) Restore(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var m map[string]Profile
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	for _, p := range m {
		// Set revalidates and recompiles the (non-serialized) CSRF regex.
		_ = s.Set(p)
	}
	return nil
}
