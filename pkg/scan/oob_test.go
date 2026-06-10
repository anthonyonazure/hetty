package scan_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid"

	"github.com/dstotijn/hetty/pkg/collab"
	"github.com/dstotijn/hetty/pkg/scan"
)

// ssrfServer fetches any http(s) URL passed in the "url" parameter, simulating
// a server-side request forgery sink.
func ssrfServer() *httptest.Server {
	client := &http.Client{Timeout: 700 * time.Millisecond}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target != "" {
			u := target
			if strings.HasPrefix(u, "//") {
				u = "http:" + u
			}
			if strings.HasPrefix(u, "http") {
				if resp, err := client.Get(u); err == nil {
					resp.Body.Close()
				}
			}
		}
		fmt.Fprint(w, "ok")
	}))
}

func TestOOBInteractionCheck(t *testing.T) {
	// Collaborator server.
	collabSrv := collab.NewServer("http://placeholder")
	collabHTTP := httptest.NewServer(collabSrv.Handler())
	defer collabHTTP.Close()
	collabSrv.SetBaseURL(collabHTTP.URL)

	// Target with an SSRF sink.
	target := ssrfServer()
	defer target.Close()

	// Speed up unrelated time-based checks.
	oldDelay := scan.CmdInjectionDelaySeconds
	scan.CmdInjectionDelaySeconds = 2
	defer func() { scan.CmdInjectionDelaySeconds = oldDelay }()

	opts := scan.DefaultOptions()
	opts.RequestTimeout = 10 * time.Second
	svc := scan.NewService(scan.Config{Repository: newMemRepo(), Options: opts})
	svc.SetOOB(collabSrv)

	entropy := ulid.Monotonic(timeReader{}, 0)
	pid := ulid.MustNew(ulid.Now(), entropy)

	// Use a non-HTTP seed value so the baseline request doesn't trigger an
	// outbound fetch; the OOB check supplies the http callback URL itself.
	base := baseGET(t, target.URL+"/?url=seed")

	res, err := svc.ScanRequest(context.Background(), pid, base)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if !hasCheck(res.Issues, "oob-interaction") {
		t.Fatalf("expected oob-interaction issue; got %s", issueIDs(res.Issues))
	}
}
