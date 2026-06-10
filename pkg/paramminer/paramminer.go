// Package paramminer discovers hidden/unlinked request parameters — Hetty's
// analogue of Burp's "Param Miner". It probes a target with candidate parameter
// names (in the query string, body, or as headers) carrying a unique canary
// value, and flags a parameter when the canary is reflected in the response or
// when the response measurably changes versus a calibrated baseline. Hidden
// parameters frequently gate debug modes, access controls, SSRF sinks and other
// high-value functionality.
package paramminer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dstotijn/hetty/pkg/ratelimit"
)

// Location selects where candidate parameters are injected.
type Location string

const (
	LocationQuery  Location = "query"
	LocationBody   Location = "body"
	LocationHeader Location = "header"
)

const canary = "hetty7r3con"

// Options configures a mining run.
type Options struct {
	Location          Location          `json:"location"`
	Wordlist          []string          `json:"wordlist"`
	Method            string            `json:"method"`
	Headers           map[string]string `json:"headers"`
	Concurrency       int               `json:"concurrency"`
	TimeoutMs         int               `json:"timeoutMs"`
	RequestsPerSecond float64           `json:"requestsPerSecond"`
}

// Finding is a discovered parameter.
type Finding struct {
	Param    string `json:"param"`
	Location string `json:"location"`
	Reason   string `json:"reason"`
	Status   int    `json:"status"`
	Length   int    `json:"length"`
}

// Result summarizes a run.
type Result struct {
	Target         string    `json:"target"`
	Location       string    `json:"location"`
	BaselineStatus int       `json:"baselineStatus"`
	BaselineLength int       `json:"baselineLength"`
	Findings       []Finding `json:"findings"`
	Requests       int       `json:"requests"`
}

// Engine runs parameter discovery.
type Engine struct {
	newClient func(timeout time.Duration) *http.Client
}

// New returns a parameter-mining engine.
func New() *Engine {
	return &Engine{
		newClient: func(timeout time.Duration) *http.Client {
			return &http.Client{
				Timeout: timeout,
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		},
	}
}

type probe struct {
	status     int
	length     int
	reflected  bool
	err        error
}

// Mine probes target for hidden parameters.
func (e *Engine) Mine(ctx context.Context, target string, opts Options) (Result, error) {
	base, err := url.Parse(target)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return Result{}, fmt.Errorf("paramminer: target must be an absolute URL")
	}

	loc := opts.Location
	if loc == "" {
		loc = LocationQuery
	}
	method := strings.ToUpper(opts.Method)
	if method == "" {
		if loc == LocationBody {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}

	words := opts.Wordlist
	if len(words) == 0 {
		words = CommonParams
	}

	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	r := &runner{
		engine:  e,
		client:  e.newClient(timeout),
		base:    base,
		method:  method,
		loc:     loc,
		headers: opts.Headers,
		limiter: ratelimit.New(ratelimit.Config{RequestsPerSecond: opts.RequestsPerSecond, MaxConcurrent: opts.Concurrency}),
	}

	// Baseline + length-noise calibration with non-existent params.
	baseline := r.do(ctx, "hetty_baseline_xyz")
	if baseline.err != nil {
		return Result{}, fmt.Errorf("paramminer: baseline request failed: %w", baseline.err)
	}
	noise := r.calibrateNoise(ctx, baseline.length)

	result := Result{
		Target:         target,
		Location:       string(loc),
		BaselineStatus: baseline.status,
		BaselineLength: baseline.length,
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		reqs = 3 // baseline + 2 calibration probes
	)

	for _, word := range words {
		word := strings.TrimSpace(word)
		if word == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := r.do(ctx, word)

			mu.Lock()
			reqs++
			mu.Unlock()

			if p.err != nil {
				return
			}

			reason := ""
			switch {
			case p.reflected:
				reason = "canary reflected"
			case p.status != baseline.status:
				reason = fmt.Sprintf("status changed %d->%d", baseline.status, p.status)
			case abs(p.length-baseline.length) > noise:
				reason = fmt.Sprintf("length changed %d->%d (noise %d)", baseline.length, p.length, noise)
			default:
				return
			}

			mu.Lock()
			result.Findings = append(result.Findings, Finding{
				Param: word, Location: string(loc), Reason: reason, Status: p.status, Length: p.length,
			})
			mu.Unlock()
		}()
	}
	wg.Wait()

	result.Requests = reqs
	return result, nil
}

type runner struct {
	engine  *Engine
	client  *http.Client
	base    *url.URL
	method  string
	loc     Location
	headers map[string]string
	limiter *ratelimit.Limiter
}

// calibrateNoise sends two non-existent params and returns a length tolerance
// that accommodates a dynamic page that varies slightly per request.
func (r *runner) calibrateNoise(ctx context.Context, baselineLen int) int {
	p1 := r.do(ctx, "hetty_noise_aaa")
	p2 := r.do(ctx, "hetty_noise_bbb")
	noise := 0
	for _, l := range []int{p1.length, p2.length} {
		if d := abs(l - baselineLen); d > noise {
			noise = d
		}
	}
	// Always allow a little slack to suppress trivial variance.
	if noise < 24 {
		noise = 24
	}
	return noise
}

func (r *runner) do(ctx context.Context, param string) probe {
	release, err := r.limiter.Acquire(ctx)
	if err != nil {
		return probe{err: err}
	}
	defer release()

	u := *r.base
	var body io.Reader
	header := http.Header{}
	for k, v := range r.headers {
		header.Set(k, v)
	}

	switch r.loc {
	case LocationBody:
		form := url.Values{}
		form.Set(param, canary)
		body = strings.NewReader(form.Encode())
		header.Set("Content-Type", "application/x-www-form-urlencoded")
	case LocationHeader:
		header.Set(param, canary)
	default: // query
		q := u.Query()
		q.Set(param, canary)
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, r.method, u.String(), body)
	if err != nil {
		return probe{err: err}
	}
	req.Header = header

	res, err := r.client.Do(req)
	if err != nil {
		return probe{err: err}
	}
	defer res.Body.Close()

	b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return probe{err: err}
	}

	return probe{
		status:    res.StatusCode,
		length:    len(b),
		reflected: strings.Contains(string(b), canary),
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
