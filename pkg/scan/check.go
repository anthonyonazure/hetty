package scan

import (
	"context"
	"sync"
)

// ActiveCheck mutates a request at a single insertion point and inspects the
// resulting responses for vulnerabilities. A check is invoked once per
// (insertion point, request) pair.
type ActiveCheck interface {
	// ID is a stable, unique identifier (e.g. "xss-reflected").
	ID() string
	// Name is a human-readable title.
	Name() string
	// Run sends payloads through the ScanContext and returns any findings.
	Run(sc *ScanContext) []Finding
}

// PassiveCheck inspects a request/response pair without sending new requests.
type PassiveCheck interface {
	ID() string
	Name() string
	Check(req *RequestTemplate, res *Response) []Finding
}

// ScanContext is handed to an ActiveCheck. It exposes the base request, the
// insertion point under test, the baseline response, and helpers to send
// mutated requests.
type ScanContext struct {
	Ctx      context.Context
	Base     *RequestTemplate
	Point    InsertionPoint
	Baseline *Response

	OOB OOBClient

	svc *Service
}

// Send replaces the insertion point's value with payload and sends the
// request.
func (sc *ScanContext) Send(payload string) (*Response, *RequestTemplate, error) {
	rt := ApplyPayload(sc.Base, sc.Point, payload, false)
	res, err := sc.svc.do(sc.Ctx, rt)

	return res, rt, err
}

// SendAppended appends payload to the insertion point's original value and
// sends the request. This preserves an otherwise-valid value, which many
// injection checks require.
func (sc *ScanContext) SendAppended(payload string) (*Response, *RequestTemplate, error) {
	rt := ApplyPayload(sc.Base, sc.Point, payload, true)
	res, err := sc.svc.do(sc.Ctx, rt)

	return res, rt, err
}

// SendRaw sends an arbitrary request template.
func (sc *ScanContext) SendRaw(rt *RequestTemplate) (*Response, error) {
	return sc.svc.do(sc.Ctx, rt)
}

// Registry holds the set of active and passive checks the scanner runs.
type Registry struct {
	mu      sync.RWMutex
	active  []ActiveCheck
	passive []PassiveCheck
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// RegisterActive adds active checks to the registry.
func (r *Registry) RegisterActive(checks ...ActiveCheck) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active = append(r.active, checks...)
}

// RegisterPassive adds passive checks to the registry.
func (r *Registry) RegisterPassive(checks ...PassiveCheck) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.passive = append(r.passive, checks...)
}

// ActiveChecks returns a snapshot of the registered active checks.
func (r *Registry) ActiveChecks() []ActiveCheck {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]ActiveCheck, len(r.active))
	copy(out, r.active)

	return out
}

// PassiveChecks returns a snapshot of the registered passive checks.
func (r *Registry) PassiveChecks() []PassiveCheck {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]PassiveCheck, len(r.passive))
	copy(out, r.passive)

	return out
}

// DefaultRegistry returns a registry populated with the built-in checks.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.RegisterActive(BuiltinActiveChecks()...)
	r.RegisterPassive(BuiltinPassiveChecks()...)

	return r
}

// safeActive runs an active check, recovering from panics so a faulty check
// (including a third-party extension check) can't crash a scan.
func safeActive(check ActiveCheck, sc *ScanContext) (findings []Finding) {
	defer func() {
		if r := recover(); r != nil {
			sc.svc.logger.Errorw("Active check panicked.", "check", check.ID(), "recover", r)
			findings = nil
		}
	}()

	return check.Run(sc)
}

func safePassive(check PassiveCheck, req *RequestTemplate, res *Response) (findings []Finding) {
	defer func() {
		_ = recover()
	}()

	return check.Check(req, res)
}
