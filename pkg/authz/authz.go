// Package authz implements an authorization tester — Hetty's analogue of the
// Burp "Autorize" and "AuthMatrix" extensions. Given a request that succeeds
// for a privileged identity, it replays the same request under one or more
// alternate identities (a lower-privileged user, and/or no authentication at
// all) and compares each response to the privileged baseline. When a lower
// identity receives substantially the same successful response, the endpoint is
// failing to enforce access control — the signature of IDOR / BOLA / broken
// access control, the highest-signal bug class in bounty work.
package authz

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dstotijn/hetty/pkg/ratelimit"
	"github.com/dstotijn/hetty/pkg/session"
)

// Header is a request header.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RequestSpec is the privileged base request to test.
type RequestSpec struct {
	Method  string   `json:"method"`
	URL     string   `json:"url"`
	Proto   string   `json:"proto"`
	Headers []Header `json:"headers"`
	Body    string   `json:"body"`
}

// Identity is an alternate identity to replay the request under. A nil Profile
// means "unauthenticated": all identity-bearing headers are stripped.
type Identity struct {
	Label   string           `json:"label"`
	Profile *session.Profile `json:"profile,omitempty"`
}

// Verdict classifies an identity's access to the resource.
type Verdict string

const (
	// VerdictBypassed means the lower identity got essentially the privileged
	// response — access control is NOT enforced.
	VerdictBypassed Verdict = "bypassed"
	// VerdictEnforced means access was properly denied or diverged.
	VerdictEnforced Verdict = "enforced"
	// VerdictAmbiguous means the result needs manual review.
	VerdictAmbiguous Verdict = "ambiguous"
)

// IdentityResult is the outcome for one alternate identity.
type IdentityResult struct {
	Label      string  `json:"label"`
	Status     int     `json:"status"`
	Length     int     `json:"length"`
	Similarity float64 `json:"similarity"`
	Verdict    Verdict `json:"verdict"`
	Note       string  `json:"note"`
	DurationMs int64   `json:"durationMs"`
	Error      string  `json:"error,omitempty"`
}

// Baseline summarizes the privileged response.
type Baseline struct {
	Status int `json:"status"`
	Length int `json:"length"`
}

// Result is the full analysis.
type Result struct {
	Baseline   Baseline         `json:"baseline"`
	Identities []IdentityResult `json:"identities"`
}

// Engine runs authorization analyses.
type Engine struct {
	client  *http.Client
	limiter *ratelimit.Limiter
	// bypassThreshold is the body-similarity ratio (0..1) at or above which a
	// matching-status response counts as bypassed.
	bypassThreshold float64
}

// Config configures an Engine.
type Config struct {
	Client          *http.Client
	Limiter         *ratelimit.Limiter
	BypassThreshold float64
}

// noRedirect makes a client return the redirect response instead of following
// it — a 302 to /login is access-control signal, not something to chase.
func noRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

// NewEngine returns an authorization-testing engine. A caller-supplied client's
// transport and cookie jar are reused, but redirect-following is always
// disabled so denials surface as 3xx rather than being chased to a login page.
func NewEngine(cfg Config) *Engine {
	var transport http.RoundTripper
	var jar http.CookieJar
	if cfg.Client != nil {
		transport = cfg.Client.Transport
		jar = cfg.Client.Jar
	}

	e := &Engine{
		client: &http.Client{
			Transport:     transport,
			Jar:           jar,
			Timeout:       30 * time.Second,
			CheckRedirect: noRedirect,
		},
		limiter:         cfg.Limiter,
		bypassThreshold: cfg.BypassThreshold,
	}
	if e.bypassThreshold <= 0 {
		e.bypassThreshold = 0.95
	}
	return e
}

type response struct {
	status int
	body   []byte
}

func (e *Engine) send(ctx context.Context, method, rawURL, proto string, header http.Header, body string) (response, error) {
	if e.limiter != nil {
		release, err := e.limiter.Acquire(ctx)
		if err != nil {
			return response{}, err
		}
		defer release()
	}

	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return response{}, err
	}
	if header != nil {
		req.Header = header
	}

	res, err := e.client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer res.Body.Close()

	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return response{}, err
	}

	return response{status: res.StatusCode, body: b}, nil
}

func headerFromSpec(headers []Header) http.Header {
	h := make(http.Header)
	for _, hdr := range headers {
		if hdr.Name != "" {
			h.Add(hdr.Name, hdr.Value)
		}
	}
	return h
}

// Analyze sends the privileged base request, then replays it under each
// identity and classifies the result.
func (e *Engine) Analyze(ctx context.Context, base RequestSpec, identities []Identity) (Result, error) {
	if base.URL == "" {
		return Result{}, fmt.Errorf("authz: base URL required")
	}

	baseHeader := headerFromSpec(base.Headers)

	baseResp, err := e.send(ctx, base.Method, base.URL, base.Proto, baseHeader, base.Body)
	if err != nil {
		return Result{}, fmt.Errorf("authz: baseline request failed: %w", err)
	}

	result := Result{
		Baseline: Baseline{Status: baseResp.status, Length: len(baseResp.body)},
	}

	for _, id := range identities {
		ir := e.analyzeIdentity(ctx, base, baseHeader, baseResp, id)
		result.Identities = append(result.Identities, ir)
	}

	return result, nil
}

func (e *Engine) analyzeIdentity(
	ctx context.Context, base RequestSpec, baseHeader http.Header, baseResp response, id Identity,
) IdentityResult {
	ir := IdentityResult{Label: id.Label}
	if ir.Label == "" {
		if id.Profile == nil {
			ir.Label = "unauthenticated"
		} else {
			ir.Label = id.Profile.Name
		}
	}

	// Build the identity's header set: start from the base request, strip the
	// privileged identity, then apply the alternate profile (if any).
	header := session.Stripped(baseHeader)
	if id.Profile != nil {
		id.Profile.Apply(header)

		// Resolve a CSRF token if the profile needs one.
		if id.Profile.CSRF != nil && id.Profile.CSRF.InjectHeader != "" {
			tok, err := id.Profile.CSRF.Resolve(ctx, e.client)
			if err == nil {
				header.Set(id.Profile.CSRF.InjectHeader, tok)
			}
		}
	}

	start := time.Now()
	resp, err := e.send(ctx, base.Method, base.URL, base.Proto, header, base.Body)
	ir.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		ir.Error = err.Error()
		ir.Verdict = VerdictAmbiguous
		ir.Note = "request failed"
		return ir
	}

	ir.Status = resp.status
	ir.Length = len(resp.body)
	ir.Similarity = Similarity(baseResp.body, resp.body)
	ir.Verdict, ir.Note = classify(baseResp, resp, ir.Similarity, e.bypassThreshold)
	return ir
}

// classify decides the verdict from the baseline and test responses.
func classify(base, test response, similarity, threshold float64) (Verdict, string) {
	// Explicit access-control denial.
	if test.status == http.StatusUnauthorized || test.status == http.StatusForbidden {
		return VerdictEnforced, fmt.Sprintf("denied with %d", test.status)
	}

	// Redirect (often to a login page) when the baseline was a success.
	if base.status >= 200 && base.status < 300 && (test.status == http.StatusFound ||
		test.status == http.StatusSeeOther || test.status == http.StatusTemporaryRedirect) {
		return VerdictEnforced, fmt.Sprintf("redirected with %d (likely to login)", test.status)
	}

	// Same status as the privileged baseline.
	if test.status == base.status {
		if similarity >= threshold {
			return VerdictBypassed, fmt.Sprintf("same status %d and %.0f%% similar body", test.status, similarity*100)
		}
		return VerdictAmbiguous, fmt.Sprintf("same status %d but only %.0f%% similar body", test.status, similarity*100)
	}

	// Different status codes — diverged, probably enforced, but flag for review
	// if the test still returned a success.
	if test.status >= 200 && test.status < 300 {
		return VerdictAmbiguous, fmt.Sprintf("different status (base %d, got %d) but still 2xx", base.status, test.status)
	}

	return VerdictEnforced, fmt.Sprintf("different status (base %d, got %d)", base.status, test.status)
}

// Similarity returns a Sørensen–Dice coefficient (0..1) over the whitespace-
// delimited token multisets of a and b. It is robust to reordering and to small
// per-user differences (e.g. a username echoed in the page) while still
// distinguishing genuinely different pages.
func Similarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	if len(a) == 0 || len(b) == 0 {
		return 0
	}

	ca := tokenCounts(a)
	cb := tokenCounts(b)

	var common, totalA, totalB int
	for tok, na := range ca {
		totalA += na
		if nb, ok := cb[tok]; ok {
			common += min(na, nb)
		}
	}
	for _, nb := range cb {
		totalB += nb
	}

	if totalA+totalB == 0 {
		return 1
	}
	return float64(2*common) / float64(totalA+totalB)
}

func tokenCounts(b []byte) map[string]int {
	counts := make(map[string]int)
	for _, tok := range bytes.Fields(b) {
		counts[string(tok)]++
	}
	return counts
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
