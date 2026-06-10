// Package intruder implements Hetty's Intruder tool: automated, customizable
// attacks that place payloads at marked positions in a base request. It
// supports the four classic attack types (sniper, battering ram, pitchfork,
// cluster bomb), payload processing rules, concurrency, and response grep
// match/extract analysis.
package intruder

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dstotijn/hetty/pkg/decoder"
	"github.com/dstotijn/hetty/pkg/ratelimit"
)

// AttackType selects how payloads are distributed across positions.
type AttackType string

const (
	Sniper       AttackType = "sniper"
	BatteringRam AttackType = "batteringram"
	Pitchfork    AttackType = "pitchfork"
	ClusterBomb  AttackType = "clusterbomb"
)

// DefaultMarker is the position marker (used in pairs, like Burp's §).
const DefaultMarker = "§"

// maxRequests caps an attack to prevent accidental runaway cluster bombs.
const maxRequests = 200000

// Header is an ordered request header.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RequestSpec is the base request, with payload positions marked.
type RequestSpec struct {
	Method  string   `json:"method"`
	URL     string   `json:"url"`
	Proto   string   `json:"proto"`
	Headers []Header `json:"headers"`
	Body    string   `json:"body"`
}

// Attack fully specifies an Intruder run.
type Attack struct {
	Type        AttackType `json:"type"`
	Base        RequestSpec `json:"base"`
	PayloadSets [][]string `json:"payloadSets"`
	Processors  []string   `json:"processors"`
	GrepMatch   []string   `json:"grepMatch"`
	GrepExtract string     `json:"grepExtract"`
	Marker      string     `json:"marker"`
	Concurrency int        `json:"concurrency"`
	TimeoutMs   int        `json:"timeoutMs"`
	Redirects   bool       `json:"followRedirects"`
	// RequestsPerSecond throttles the attack (0 = unthrottled). It is combined
	// with any engine-wide limiter.
	RequestsPerSecond float64 `json:"requestsPerSecond"`
}

// Result is a single attack request's outcome.
type Result struct {
	Index      int             `json:"index"`
	Payloads   []string        `json:"payloads"`
	Position   int             `json:"position"` // sniper only; -1 otherwise
	Status     int             `json:"status"`
	Length     int             `json:"length"`
	DurationMs int64           `json:"durationMs"`
	Matches    map[string]bool `json:"matches,omitempty"`
	Extract    string          `json:"extract,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// Summary aggregates an attack.
type Summary struct {
	AttackType AttackType `json:"attackType"`
	Positions  int        `json:"positions"`
	Requests   int        `json:"requests"`
}

// Engine runs Intruder attacks.
type Engine struct {
	newClient func(timeout time.Duration, redirects bool) *http.Client
	limiter   *ratelimit.Limiter
}

// NewEngine returns an Intruder engine.
func NewEngine() *Engine {
	return &Engine{newClient: defaultClient}
}

// SetLimiter installs an engine-wide rate limiter (e.g. a global politeness
// cap). It is applied in addition to any per-attack rate.
func (e *Engine) SetLimiter(l *ratelimit.Limiter) {
	e.limiter = l
}

func defaultClient(timeout time.Duration, redirects bool) *http.Client {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		//nolint:gosec
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	c := &http.Client{Transport: transport, Timeout: timeout}
	if !redirects {
		c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	}

	return c
}

// CountPositions returns the number of payload positions in a base request.
func CountPositions(base RequestSpec, marker string) int {
	if marker == "" {
		marker = DefaultMarker
	}
	tmpl := parseTemplate(base, marker)
	return tmpl.positions
}

// Run executes the attack, returning a summary and per-request results ordered
// by request index.
func (e *Engine) Run(ctx context.Context, attack Attack) (Summary, []Result, error) {
	marker := attack.Marker
	if marker == "" {
		marker = DefaultMarker
	}

	tmpl := parseTemplate(attack.Base, marker)

	if tmpl.positions == 0 {
		return Summary{}, nil, fmt.Errorf("intruder: no payload positions found (mark them with %q)", marker)
	}

	sets, err := processSets(attack.PayloadSets, attack.Processors)
	if err != nil {
		return Summary{}, nil, err
	}

	jobs, err := generateJobs(attack.Type, tmpl, sets)
	if err != nil {
		return Summary{}, nil, err
	}

	if len(jobs) > maxRequests {
		return Summary{}, nil, fmt.Errorf("intruder: attack would issue %d requests, exceeding the %d limit", len(jobs), maxRequests)
	}

	var grepExtract *regexp.Regexp
	if attack.GrepExtract != "" {
		grepExtract, err = regexp.Compile(attack.GrepExtract)
		if err != nil {
			return Summary{}, nil, fmt.Errorf("intruder: invalid grep-extract regex: %w", err)
		}
	}

	timeout := time.Duration(attack.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := e.newClient(timeout, attack.Redirects)

	var runLimiter *ratelimit.Limiter
	if attack.RequestsPerSecond > 0 {
		runLimiter = ratelimit.New(ratelimit.Config{RequestsPerSecond: attack.RequestsPerSecond})
	}

	concurrency := attack.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	results := make([]Result, len(jobs))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := range jobs {
		i := i
		wg.Add(1)
		sem <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			results[i] = e.runJob(ctx, client, tmpl, jobs[i], attack.GrepMatch, grepExtract, runLimiter)
		}()
	}

	wg.Wait()

	sort.Slice(results, func(a, b int) bool { return results[a].Index < results[b].Index })

	return Summary{
		AttackType: attack.Type,
		Positions:  tmpl.positions,
		Requests:   len(jobs),
	}, results, nil
}

func (e *Engine) runJob(ctx context.Context, client *http.Client, tmpl template, j job, grepMatch []string, grepExtract *regexp.Regexp, runLimiter *ratelimit.Limiter) Result {
	res := Result{Index: j.index, Payloads: j.payloads, Position: j.position}

	method, rawURL, headers, body := tmpl.render(j.values)

	httpReq, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(body))
	if err != nil {
		res.Error = err.Error()
		return res
	}
	for _, h := range headers {
		httpReq.Header.Add(h.Name, h.Value)
	}

	// Rate limiting: engine-wide cap, then any per-attack cap. Both limiters may
	// be nil (unlimited); Acquire handles that.
	releaseEngine, err := e.limiter.Acquire(ctx)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer releaseEngine()

	releaseRun, err := runLimiter.Acquire(ctx)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer releaseRun()

	start := time.Now()
	httpRes, err := client.Do(httpReq)
	if err != nil {
		res.Error = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	defer httpRes.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(httpRes.Body, 5<<20))
	res.DurationMs = time.Since(start).Milliseconds()
	res.Status = httpRes.StatusCode
	res.Length = len(respBody)

	if len(grepMatch) > 0 {
		res.Matches = make(map[string]bool, len(grepMatch))
		bodyStr := string(respBody)
		for _, m := range grepMatch {
			res.Matches[m] = strings.Contains(bodyStr, m)
		}
	}

	if grepExtract != nil {
		if sm := grepExtract.FindSubmatch(respBody); sm != nil {
			if len(sm) > 1 {
				res.Extract = string(sm[1])
			} else {
				res.Extract = string(sm[0])
			}
		}
	}

	return res
}

// --- Template parsing & rendering ------------------------------------------

type segmentedField struct {
	kind     string // "url", "header", "body"
	name     string // header name
	literals []string
	posIdx   []int
}

func (sf segmentedField) render(values []string) string {
	var b strings.Builder
	b.WriteString(sf.literals[0])
	for k, idx := range sf.posIdx {
		b.WriteString(values[idx])
		b.WriteString(sf.literals[k+1])
	}
	return b.String()
}

type template struct {
	method    string
	url       segmentedField
	headers   []segmentedField
	body      segmentedField
	positions int
	originals []string
}

func parseTemplate(base RequestSpec, marker string) template {
	tmpl := template{method: base.Method}
	gpos := 0

	tmpl.url = parseField("url", "", base.URL, marker, &gpos, &tmpl.originals)
	for _, h := range base.Headers {
		tmpl.headers = append(tmpl.headers, parseField("header", h.Name, h.Value, marker, &gpos, &tmpl.originals))
	}
	tmpl.body = parseField("body", "", base.Body, marker, &gpos, &tmpl.originals)

	tmpl.positions = gpos

	return tmpl
}

func parseField(kind, name, s, marker string, gpos *int, originals *[]string) segmentedField {
	parts := strings.Split(s, marker)
	sf := segmentedField{kind: kind, name: name}
	sf.literals = append(sf.literals, parts[0])

	for i := 1; i < len(parts); i += 2 {
		original := parts[i]
		*originals = append(*originals, original)
		sf.posIdx = append(sf.posIdx, *gpos)
		*gpos++

		next := ""
		if i+1 < len(parts) {
			next = parts[i+1]
		}
		sf.literals = append(sf.literals, next)
	}

	return sf
}

// render produces the concrete request for a set of position values.
func (t template) render(values []string) (method, url string, headers []Header, body string) {
	method = t.method
	url = t.url.render(values)
	for _, hf := range t.headers {
		headers = append(headers, Header{Name: hf.name, Value: hf.render(values)})
	}
	body = t.body.render(values)
	return method, url, headers, body
}

// --- Job generation --------------------------------------------------------

type job struct {
	index    int
	values   []string
	payloads []string
	position int
}

func generateJobs(attackType AttackType, tmpl template, sets [][]string) ([]job, error) {
	n := tmpl.positions
	originals := tmpl.originals

	switch attackType {
	case Sniper:
		if len(sets) == 0 || len(sets[0]) == 0 {
			return nil, fmt.Errorf("intruder: sniper attack requires a payload set")
		}
		var jobs []job
		idx := 0
		for pos := 0; pos < n; pos++ {
			for _, pl := range sets[0] {
				values := append([]string(nil), originals...)
				values[pos] = pl
				jobs = append(jobs, job{index: idx, values: values, payloads: []string{pl}, position: pos})
				idx++
			}
		}
		return jobs, nil

	case BatteringRam:
		if len(sets) == 0 || len(sets[0]) == 0 {
			return nil, fmt.Errorf("intruder: battering ram attack requires a payload set")
		}
		var jobs []job
		for idx, pl := range sets[0] {
			values := make([]string, n)
			for i := range values {
				values[i] = pl
			}
			jobs = append(jobs, job{index: idx, values: values, payloads: []string{pl}, position: -1})
		}
		return jobs, nil

	case Pitchfork:
		if len(sets) < n {
			return nil, fmt.Errorf("intruder: pitchfork needs one payload set per position (have %d, need %d)", len(sets), n)
		}
		minLen := len(sets[0])
		for i := 1; i < n; i++ {
			if len(sets[i]) < minLen {
				minLen = len(sets[i])
			}
		}
		var jobs []job
		for j := 0; j < minLen; j++ {
			values := append([]string(nil), originals...)
			payloads := make([]string, n)
			for i := 0; i < n; i++ {
				values[i] = sets[i][j]
				payloads[i] = sets[i][j]
			}
			jobs = append(jobs, job{index: j, values: values, payloads: payloads, position: -1})
		}
		return jobs, nil

	case ClusterBomb:
		if len(sets) < n {
			return nil, fmt.Errorf("intruder: cluster bomb needs one payload set per position (have %d, need %d)", len(sets), n)
		}
		return clusterBomb(n, originals, sets), nil

	default:
		return nil, fmt.Errorf("intruder: unknown attack type %q", attackType)
	}
}

func clusterBomb(n int, originals []string, sets [][]string) []job {
	for i := 0; i < n; i++ {
		if len(sets[i]) == 0 {
			return nil
		}
	}

	var jobs []job
	counter := make([]int, n)
	idx := 0

	for {
		values := append([]string(nil), originals...)
		payloads := make([]string, n)
		for i := 0; i < n; i++ {
			values[i] = sets[i][counter[i]]
			payloads[i] = sets[i][counter[i]]
		}
		jobs = append(jobs, job{index: idx, values: values, payloads: payloads, position: -1})
		idx++

		if len(jobs) > maxRequests {
			return jobs
		}

		// Increment the odometer.
		k := n - 1
		for k >= 0 {
			counter[k]++
			if counter[k] < len(sets[k]) {
				break
			}
			counter[k] = 0
			k--
		}
		if k < 0 {
			break
		}
	}

	return jobs
}

// --- Payload processing ----------------------------------------------------

func processSets(sets [][]string, processors []string) ([][]string, error) {
	if len(processors) == 0 {
		return sets, nil
	}

	out := make([][]string, len(sets))
	for i, set := range sets {
		processed := make([]string, len(set))
		for j, p := range set {
			v, err := applyProcessors(p, processors)
			if err != nil {
				return nil, err
			}
			processed[j] = v
		}
		out[i] = processed
	}

	return out, nil
}

func applyProcessors(payload string, processors []string) (string, error) {
	cur := payload
	for _, proc := range processors {
		switch {
		case proc == "urlencode":
			b, _ := decoder.Apply("url", decoder.OpEncode, []byte(cur))
			cur = string(b)
		case proc == "base64":
			b, _ := decoder.Apply("base64", decoder.OpEncode, []byte(cur))
			cur = string(b)
		case proc == "upper":
			cur = strings.ToUpper(cur)
		case proc == "lower":
			cur = strings.ToLower(cur)
		case proc == "md5", proc == "sha1", proc == "sha256":
			b, _ := decoder.Apply(proc, decoder.OpEncode, []byte(cur))
			cur = string(b)
		case strings.HasPrefix(proc, "prefix:"):
			cur = strings.TrimPrefix(proc, "prefix:") + cur
		case strings.HasPrefix(proc, "suffix:"):
			cur += strings.TrimPrefix(proc, "suffix:")
		default:
			return "", fmt.Errorf("intruder: unknown payload processor %q", proc)
		}
	}

	return cur, nil
}

// From helpers ------------------------------------------------------------

// BuildSpecFromRaw is a convenience that splits raw header strings into a
// RequestSpec. Each header is "Name: Value".
func BuildSpecFromRaw(method, rawURL, proto string, headerLines []string, body string) RequestSpec {
	spec := RequestSpec{Method: method, URL: rawURL, Proto: proto, Body: body}
	for _, line := range headerLines {
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		spec.Headers = append(spec.Headers, Header{
			Name:  strings.TrimSpace(line[:idx]),
			Value: strings.TrimSpace(line[idx+1:]),
		})
	}
	return spec
}
