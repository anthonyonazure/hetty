package scan

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/oklog/ulid"

	"github.com/dstotijn/hetty/pkg/proxy"
)

// ResponseModifier returns proxy middleware that passively scans every proxied
// response (when PassiveOnProxy is enabled and a project is active). Scanning
// runs asynchronously so it never adds latency to the proxied response, and the
// full response body is always restored for the client.
func (svc *Service) ResponseModifier(next proxy.ResponseModifyFunc) proxy.ResponseModifyFunc {
	return func(res *http.Response) error {
		if err := next(res); err != nil {
			return err
		}

		if !svc.opts.PassiveOnProxy {
			return nil
		}

		projectID := svc.ActiveProjectID()
		if projectID.Compare(ulid.ULID{}) == 0 {
			return nil
		}

		// Read the full body and restore it for the client.
		var body []byte
		if res.Body != nil {
			b, err := io.ReadAll(res.Body)
			if err != nil {
				return nil
			}
			res.Body = io.NopCloser(bytes.NewReader(b))
			body = b
		}

		// Use a (possibly capped) copy for analysis.
		analyzeBody := body
		if len(analyzeBody) > maxRespBodyBytes {
			analyzeBody = analyzeBody[:maxRespBodyBytes]
		}

		sr := &Response{
			Proto:      res.Proto,
			StatusCode: res.StatusCode,
			Header:     res.Header.Clone(),
			Body:       append([]byte(nil), analyzeBody...),
		}

		var reqTmpl *RequestTemplate
		if res.Request != nil {
			reqTmpl, _ = RequestTemplateFromHTTP(res.Request)
		}

		go func() {
			if _, err := svc.PassiveScan(context.Background(), projectID, reqTmpl, sr); err != nil {
				svc.logger.Debugw("Passive proxy scan failed.", "error", err)
			}
		}()

		return nil
	}
}
