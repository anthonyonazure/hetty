package scan_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/oklog/ulid"

	"github.com/dstotijn/hetty/pkg/scan"
)

// hostPoisonServer reflects the X-Forwarded-Host header into the response body,
// simulating an app that builds links from client-controlled host headers.
func hostPoisonServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		fmt.Fprintf(w, `<html><a href="https://%s/reset">reset</a> q=%s</html>`, host, r.URL.Query().Get("q"))
	}))
}

func TestHostHeaderInjectionCheck(t *testing.T) {
	target := hostPoisonServer()
	defer target.Close()

	opts := scan.DefaultOptions()
	opts.RequestTimeout = 5 * time.Second
	svc := scan.NewService(scan.Config{Repository: newMemRepo(), Options: opts})

	entropy := ulid.Monotonic(timeReader{}, 0)
	pid := ulid.MustNew(ulid.Now(), entropy)

	// A query param gives the scan at least one insertion point so the
	// per-request host-header check fires on the first point.
	base := baseGET(t, target.URL+"/?q=hello")

	res, err := svc.ScanRequest(context.Background(), pid, base)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !hasCheck(res.Issues, "host-header-injection") {
		t.Fatalf("expected host-header-injection issue; got %s", issueIDs(res.Issues))
	}
}
