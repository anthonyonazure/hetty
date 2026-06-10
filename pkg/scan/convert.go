package scan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/oklog/ulid"
)

// NewRequestTemplate builds a RequestTemplate from primitive fields.
func NewRequestTemplate(method string, u *url.URL, proto string, header http.Header, body []byte) *RequestTemplate {
	if header == nil {
		header = make(http.Header)
	}

	return &RequestTemplate{
		Method: method,
		URL:    u,
		Proto:  proto,
		Header: header.Clone(),
		Body:   append([]byte(nil), body...),
	}
}

// RequestTemplateFromHTTP builds a RequestTemplate from an *http.Request,
// reading and restoring its body so the caller can keep using it.
func RequestTemplateFromHTTP(r *http.Request) (*RequestTemplate, error) {
	var body []byte

	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("scan: failed to read request body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		body = b
	}

	u := r.URL
	if u != nil && u.Host == "" && r.Host != "" {
		clone := *u
		clone.Host = r.Host
		if clone.Scheme == "" {
			clone.Scheme = "https"
		}
		u = &clone
	}

	return &RequestTemplate{
		Method: r.Method,
		URL:    u,
		Proto:  r.Proto,
		Header: r.Header.Clone(),
		Body:   body,
	}, nil
}

// ResponseFromHTTP builds a scan.Response from an *http.Response, reading and
// restoring its body.
func ResponseFromHTTP(r *http.Response) (*Response, error) {
	var body []byte

	if r.Body != nil {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxRespBodyBytes))
		if err != nil {
			return nil, fmt.Errorf("scan: failed to read response body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		body = b
	}

	return &Response{
		Proto:      r.Proto,
		StatusCode: r.StatusCode,
		Header:     r.Header.Clone(),
		Body:       body,
	}, nil
}

// AddIssue records a single finding (e.g. one raised by an extension) as an
// issue under the given project, applying the same de-duplication as scans.
func (svc *Service) AddIssue(ctx context.Context, projectID ulid.ULID, checkID string, base *RequestTemplate, point *InsertionPoint, f Finding) ([]Issue, error) {
	if projectID.Compare(ulid.ULID{}) == 0 {
		return nil, fmt.Errorf("scan: project ID must be set")
	}

	return svc.persist(ctx, projectID, []enriched{{
		checkID: checkID,
		base:    base,
		point:   point,
		finding: f,
	}})
}

// PassiveScan runs the registered passive checks against a single
// request/response pair and stores any new issues.
func (svc *Service) PassiveScan(ctx context.Context, projectID ulid.ULID, req *RequestTemplate, res *Response) ([]Issue, error) {
	if projectID.Compare(ulid.ULID{}) == 0 {
		return nil, fmt.Errorf("scan: project ID must be set")
	}

	var items []enriched

	for _, pc := range svc.registry.PassiveChecks() {
		for _, f := range safePassive(pc, req, res) {
			items = append(items, enriched{checkID: pc.ID(), base: req, finding: f})
		}
	}

	if len(items) == 0 {
		return nil, nil
	}

	return svc.persist(ctx, projectID, items)
}
