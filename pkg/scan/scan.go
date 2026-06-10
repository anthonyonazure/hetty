// Package scan implements an active and passive vulnerability scanner for
// Hetty. It mutates HTTP requests at discovered insertion points, sends the
// crafted requests, and analyzes the responses using a set of pluggable
// checks. Findings are persisted as Issues through a Repository.
package scan

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/oklog/ulid"

	"github.com/dstotijn/hetty/pkg/log"
	"github.com/dstotijn/hetty/pkg/ratelimit"
)

//nolint:gosec
var ulidEntropy = rand.New(rand.NewSource(time.Now().UnixNano()))

var ulidMu sync.Mutex

func newULID() ulid.ULID {
	ulidMu.Lock()
	defer ulidMu.Unlock()

	return ulid.MustNew(ulid.Timestamp(time.Now()), ulidEntropy)
}

// maxRespBodyBytes caps how much of a response body the scanner reads and
// stores, to avoid unbounded memory usage on large responses.
const maxRespBodyBytes = 2 << 20 // 2 MiB

// Severity classifies the impact of an Issue.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Confidence expresses how certain a check is about a finding.
type Confidence string

const (
	ConfidenceTentative Confidence = "tentative"
	ConfidenceFirm      Confidence = "firm"
	ConfidenceCertain   Confidence = "certain"
)

// Issue is a persisted scanner finding.
type Issue struct {
	ID          ulid.ULID  `json:"id"`
	ProjectID   ulid.ULID  `json:"projectId"`
	CheckID     string     `json:"checkId"`
	Name        string     `json:"name"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Description string     `json:"description"`
	Remediation string     `json:"remediation"`
	URL         string     `json:"url"`
	Method      string     `json:"method"`
	Param       string     `json:"param"`
	Evidence    string     `json:"evidence"`
	Payload     string     `json:"payload"`
	Fingerprint string     `json:"fingerprint"`
	CreatedAt   time.Time  `json:"createdAt"`

	Request  *CapturedRequest  `json:"request,omitempty"`
	Response *CapturedResponse `json:"response,omitempty"`
}

// CapturedRequest is a serializable snapshot of the request that produced an
// Issue.
type CapturedRequest struct {
	Method string      `json:"method"`
	URL    string      `json:"url"`
	Proto  string      `json:"proto"`
	Header http.Header `json:"header"`
	Body   []byte      `json:"body"`
}

// CapturedResponse is a serializable snapshot of the response that produced an
// Issue.
type CapturedResponse struct {
	Proto      string      `json:"proto"`
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Body       []byte      `json:"body"`
}

// RequestTemplate is the in-memory representation of a request the scanner
// mutates and sends.
type RequestTemplate struct {
	Method string `json:"method"`
	URL    *url.URL
	Proto  string      `json:"proto"`
	Header http.Header `json:"header"`
	Body   []byte      `json:"body"`
}

// Clone returns a deep copy of the template, safe to mutate independently.
func (rt *RequestTemplate) Clone() *RequestTemplate {
	c := &RequestTemplate{
		Method: rt.Method,
		Proto:  rt.Proto,
	}

	if rt.URL != nil {
		u := *rt.URL
		c.URL = &u
	}

	if rt.Header != nil {
		c.Header = rt.Header.Clone()
	} else {
		c.Header = make(http.Header)
	}

	if rt.Body != nil {
		c.Body = append([]byte(nil), rt.Body...)
	}

	return c
}

func (rt *RequestTemplate) captured() *CapturedRequest {
	cr := &CapturedRequest{
		Method: rt.Method,
		Proto:  rt.Proto,
		Header: rt.Header.Clone(),
		Body:   append([]byte(nil), rt.Body...),
	}
	if rt.URL != nil {
		cr.URL = rt.URL.String()
	}

	return cr
}

// Response is the in-memory representation of a scanner response.
type Response struct {
	Proto      string      `json:"proto"`
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Body       []byte      `json:"body"`
	Duration   time.Duration
}

func (res *Response) captured() *CapturedResponse {
	if res == nil {
		return nil
	}

	return &CapturedResponse{
		Proto:      res.Proto,
		StatusCode: res.StatusCode,
		Header:     res.Header.Clone(),
		Body:       append([]byte(nil), res.Body...),
	}
}

// Finding is what a Check returns. The Service enriches it into an Issue.
type Finding struct {
	Name        string     `json:"name"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Description string     `json:"description"`
	Remediation string     `json:"remediation"`
	Evidence    string     `json:"evidence"`
	Payload     string     `json:"payload"`

	// DedupKey, when set, is mixed into the issue fingerprint so a check can
	// control de-duplication granularity. When empty, the finding Name is used.
	DedupKey string

	Request  *RequestTemplate
	Response *Response
}

// Options configures scanner behavior.
type Options struct {
	// Concurrency is the maximum number of in-flight scan tasks.
	Concurrency int
	// RequestTimeout is the per-request timeout. It must exceed the longest
	// time-based payload delay used by active checks.
	RequestTimeout time.Duration
	// IncludeHeaders enables header insertion points (User-Agent, Referer).
	IncludeHeaders bool
	// IncludeCookies enables cookie insertion points.
	IncludeCookies bool
	// PassiveOnProxy enables automatic passive scanning of proxied traffic.
	PassiveOnProxy bool
	// RequestsPerSecond caps the scanner's outbound request rate (0 =
	// unthrottled), for staying within a target's politeness limits.
	RequestsPerSecond float64
}

// DefaultOptions returns sensible scanner defaults.
func DefaultOptions() Options {
	return Options{
		Concurrency:    8,
		RequestTimeout: 20 * time.Second,
		IncludeHeaders: false,
		IncludeCookies: true,
		PassiveOnProxy: true,
	}
}

// Repository persists and retrieves scanner issues.
type Repository interface {
	StoreIssue(ctx context.Context, issue Issue) error
	FindIssues(ctx context.Context, projectID ulid.ULID) ([]Issue, error)
	FindIssueByID(ctx context.Context, projectID, id ulid.ULID) (Issue, error)
	ClearIssues(ctx context.Context, projectID ulid.ULID) error
}

// Config is the Service configuration.
type Config struct {
	Repository Repository
	Registry   *Registry
	HTTPClient *http.Client
	Logger     log.Logger
	Options    Options
}

// OOBClient is implemented by an out-of-band interaction server (e.g.
// pkg/collab). When set on the Service, blind-vulnerability checks use it to
// detect callbacks from the target.
type OOBClient interface {
	// NewToken issues a unique token and the callback URL to embed in a payload.
	NewToken() (token, url string)
	// InteractionCount returns how many callbacks have been recorded for a token.
	InteractionCount(token string) int
}

// Service orchestrates scans and stores issues.
type Service struct {
	repo            Repository
	registry        *Registry
	httpClient      *http.Client
	logger          log.Logger
	opts            Options
	activeProjectID ulid.ULID
	oob             OOBClient
	limiter         *ratelimit.Limiter

	mu   sync.Mutex
	seen map[ulid.ULID]map[string]struct{}
}

// NewService returns a new scanner Service.
func NewService(cfg Config) *Service {
	svc := &Service{
		repo:     cfg.Repository,
		registry: cfg.Registry,
		logger:   cfg.Logger,
		opts:     cfg.Options,
		seen:     make(map[ulid.ULID]map[string]struct{}),
	}

	if svc.registry == nil {
		svc.registry = DefaultRegistry()
	}

	if svc.logger == nil {
		svc.logger = log.NewNopLogger()
	}

	if svc.opts.Concurrency <= 0 {
		svc.opts = DefaultOptions()
	}

	svc.httpClient = cfg.HTTPClient
	if svc.httpClient == nil {
		svc.httpClient = newScanHTTPClient(svc.opts.RequestTimeout)
	}

	if svc.opts.RequestsPerSecond > 0 {
		svc.limiter = ratelimit.New(ratelimit.Config{RequestsPerSecond: svc.opts.RequestsPerSecond})
	}

	return svc
}

// SetLimiter installs a rate limiter applied to every scanner request. It
// overrides any limiter derived from Options.RequestsPerSecond.
func (svc *Service) SetLimiter(l *ratelimit.Limiter) {
	svc.limiter = l
}

func newScanHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// The scanner targets arbitrary hosts during authorized testing; we do
		// not want TLS validation to abort a scan.
		//nolint:gosec
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Do not follow redirects: open-redirect detection and accurate status
		// inspection both depend on seeing the raw 3xx response.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// SetOOB configures the out-of-band interaction client used by blind checks.
func (svc *Service) SetOOB(client OOBClient) {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	svc.oob = client
}

// SetActiveProjectID sets the project issues are stored under.
func (svc *Service) SetActiveProjectID(id ulid.ULID) {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	svc.activeProjectID = id
}

// ActiveProjectID returns the active project ID.
func (svc *Service) ActiveProjectID() ulid.ULID {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	return svc.activeProjectID
}

// Registry returns the check registry, allowing callers (e.g. the extension
// engine) to register additional checks.
func (svc *Service) Registry() *Registry {
	return svc.registry
}

// Options returns a copy of the scanner options.
func (svc *Service) Options() Options {
	return svc.opts
}

// Result summarizes a completed scan.
type Result struct {
	BaseRequests int
	TasksRun     int
	Issues       []Issue
}

// ScanRequest runs a full active + passive scan against a single base request
// and stores any issues found. The projectID determines where issues are
// stored.
func (svc *Service) ScanRequest(ctx context.Context, projectID ulid.ULID, base *RequestTemplate) (Result, error) {
	return svc.ScanRequests(ctx, projectID, []*RequestTemplate{base})
}

// ScanRequests runs scans against several base requests.
func (svc *Service) ScanRequests(ctx context.Context, projectID ulid.ULID, bases []*RequestTemplate) (Result, error) {
	if projectID.Compare(ulid.ULID{}) == 0 {
		return Result{}, fmt.Errorf("scan: project ID must be set")
	}

	result := Result{BaseRequests: len(bases)}

	concurrency := svc.opts.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	sem := make(chan struct{}, concurrency)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		findings []enriched
		tasks    int
	)

	emit := func(items []enriched) {
		mu.Lock()
		findings = append(findings, items...)
		mu.Unlock()
	}

	for _, base := range bases {
		base := base
		if base == nil || base.URL == nil {
			continue
		}

		// Baseline (unmodified) response, used by checks for comparison and by
		// passive checks.
		baseline, err := svc.do(ctx, base)
		if err != nil {
			svc.logger.Debugw("Scan baseline request failed.", "url", base.URL.String(), "error", err)
		}

		// Passive checks on the baseline response.
		if baseline != nil {
			for _, pc := range svc.registry.PassiveChecks() {
				for _, f := range safePassive(pc, base, baseline) {
					emit([]enriched{{checkID: pc.ID(), base: base, finding: f}})
				}
			}
		}

		points := BuildInsertionPoints(base, svc.opts)
		activeChecks := svc.registry.ActiveChecks()

		for _, point := range points {
			for _, check := range activeChecks {
				point := point
				check := check
				tasks++

				wg.Add(1)
				sem <- struct{}{}

				go func() {
					defer wg.Done()
					defer func() { <-sem }()

					sc := &ScanContext{
						Ctx:      ctx,
						Base:     base,
						Point:    point,
						Baseline: baseline,
						OOB:      svc.oob,
						svc:      svc,
					}

					for _, f := range safeActive(check, sc) {
						emit([]enriched{{checkID: check.ID(), base: base, point: &point, finding: f}})
					}
				}()
			}
		}
	}

	wg.Wait()
	result.TasksRun = tasks

	issues, err := svc.persist(ctx, projectID, findings)
	if err != nil {
		return result, err
	}

	result.Issues = issues

	return result, nil
}

type enriched struct {
	checkID string
	base    *RequestTemplate
	point   *InsertionPoint
	finding Finding
}

// persist converts findings into issues, de-duplicates them, and stores new
// ones.
func (svc *Service) persist(ctx context.Context, projectID ulid.ULID, items []enriched) ([]Issue, error) {
	if err := svc.loadSeen(ctx, projectID); err != nil {
		return nil, err
	}

	var stored []Issue

	for _, item := range items {
		issue := svc.toIssue(projectID, item)

		svc.mu.Lock()
		seen := svc.seen[projectID]
		if _, dup := seen[issue.Fingerprint]; dup {
			svc.mu.Unlock()
			continue
		}
		seen[issue.Fingerprint] = struct{}{}
		svc.mu.Unlock()

		if err := svc.repo.StoreIssue(ctx, issue); err != nil {
			return stored, fmt.Errorf("scan: failed to store issue: %w", err)
		}

		stored = append(stored, issue)
	}

	sort.SliceStable(stored, func(i, j int) bool {
		return severityRank(stored[i].Severity) > severityRank(stored[j].Severity)
	})

	return stored, nil
}

func (svc *Service) toIssue(projectID ulid.ULID, item enriched) Issue {
	f := item.finding

	reqTmpl := f.Request
	if reqTmpl == nil {
		reqTmpl = item.base
	}

	param := ""
	if item.point != nil {
		param = item.point.Name
	}

	method := ""
	urlStr := ""
	if reqTmpl != nil {
		method = reqTmpl.Method
		if reqTmpl.URL != nil {
			urlStr = reqTmpl.URL.String()
		}
	}

	dedup := f.DedupKey
	if dedup == "" {
		dedup = f.Name
	}

	urlPath := ""
	if reqTmpl != nil && reqTmpl.URL != nil {
		urlPath = reqTmpl.URL.Host + reqTmpl.URL.Path
	}

	fingerprint := fmt.Sprintf("%s|%s|%s|%s|%s", item.checkID, method, urlPath, param, dedup)

	var capReq *CapturedRequest
	if reqTmpl != nil {
		capReq = reqTmpl.captured()
	}

	return Issue{
		ID:          newULID(),
		ProjectID:   projectID,
		CheckID:     item.checkID,
		Name:        f.Name,
		Severity:    f.Severity,
		Confidence:  f.Confidence,
		Description: f.Description,
		Remediation: f.Remediation,
		URL:         urlStr,
		Method:      method,
		Param:       param,
		Evidence:    f.Evidence,
		Payload:     f.Payload,
		Fingerprint: fingerprint,
		CreatedAt:   time.Now().UTC(),
		Request:     capReq,
		Response:    f.Response.captured(),
	}
}

func (svc *Service) loadSeen(ctx context.Context, projectID ulid.ULID) error {
	svc.mu.Lock()
	_, ok := svc.seen[projectID]
	svc.mu.Unlock()

	if ok {
		return nil
	}

	existing, err := svc.repo.FindIssues(ctx, projectID)
	if err != nil {
		return fmt.Errorf("scan: failed to load existing issues: %w", err)
	}

	set := make(map[string]struct{}, len(existing))
	for _, iss := range existing {
		set[iss.Fingerprint] = struct{}{}
	}

	svc.mu.Lock()
	svc.seen[projectID] = set
	svc.mu.Unlock()

	return nil
}

// do executes a request template and returns the response.
func (svc *Service) do(ctx context.Context, rt *RequestTemplate) (*Response, error) {
	body := rt.Body
	httpReq, err := http.NewRequestWithContext(ctx, rt.Method, rt.URL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("scan: failed to build request: %w", err)
	}

	if rt.Header != nil {
		httpReq.Header = rt.Header.Clone()
	}

	// Let net/http compute Content-Length from the body to avoid stale values.
	httpReq.Header.Del("Content-Length")
	httpReq.ContentLength = int64(len(body))

	// Rate limiting (nil limiter = unthrottled).
	release, err := svc.limiter.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	start := time.Now()

	res, err := svc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("scan: request failed: %w", err)
	}
	defer res.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(res.Body, maxRespBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("scan: failed to read response body: %w", err)
	}

	return &Response{
		Proto:      res.Proto,
		StatusCode: res.StatusCode,
		Header:     res.Header,
		Body:       respBody,
		Duration:   time.Since(start),
	}, nil
}

// FindIssues returns stored issues for a project.
func (svc *Service) FindIssues(ctx context.Context, projectID ulid.ULID) ([]Issue, error) {
	return svc.repo.FindIssues(ctx, projectID)
}

// FindIssueByID returns a single stored issue.
func (svc *Service) FindIssueByID(ctx context.Context, projectID, id ulid.ULID) (Issue, error) {
	return svc.repo.FindIssueByID(ctx, projectID, id)
}

// ClearIssues removes all issues for a project.
func (svc *Service) ClearIssues(ctx context.Context, projectID ulid.ULID) error {
	svc.mu.Lock()
	delete(svc.seen, projectID)
	svc.mu.Unlock()

	return svc.repo.ClearIssues(ctx, projectID)
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
