package scan_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid"

	"github.com/dstotijn/hetty/pkg/scan"
)

// memRepo is an in-memory scan.Repository for tests.
type memRepo struct {
	mu     sync.Mutex
	issues map[ulid.ULID][]scan.Issue
}

func newMemRepo() *memRepo {
	return &memRepo{issues: make(map[ulid.ULID][]scan.Issue)}
}

func (r *memRepo) StoreIssue(_ context.Context, issue scan.Issue) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.issues[issue.ProjectID] = append(r.issues[issue.ProjectID], issue)
	return nil
}

func (r *memRepo) FindIssues(_ context.Context, projectID ulid.ULID) ([]scan.Issue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]scan.Issue, len(r.issues[projectID]))
	copy(out, r.issues[projectID])
	return out, nil
}

func (r *memRepo) FindIssueByID(_ context.Context, projectID, id ulid.ULID) (scan.Issue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, iss := range r.issues[projectID] {
		if iss.ID.Compare(id) == 0 {
			return iss, nil
		}
	}
	return scan.Issue{}, fmt.Errorf("not found")
}

func (r *memRepo) ClearIssues(_ context.Context, projectID ulid.ULID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.issues, projectID)
	return nil
}

var sstiRe = regexp.MustCompile(`\{\{(\d+)\*(\d+)\}\}`)

// vulnerableServer is a deliberately-insecure server used to exercise checks.
func vulnerableServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/reflect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "VulnServer/1.0")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>Hello %s</body></html>", r.URL.Query().Get("q"))
	})

	mux.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")
		if regexpQuote.MatchString(id) {
			fmt.Fprint(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
			return
		}
		fmt.Fprintf(w, "<html>id=%s</html>", id)
	})

	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)
	})

	mux.HandleFunc("/ssti", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		if m := sstiRe.FindStringSubmatch(name); m != nil {
			a, _ := strconv.Atoi(m[1])
			b, _ := strconv.Atoi(m[2])
			fmt.Fprintf(w, "<html>Hello %d</html>", a*b)
			return
		}
		fmt.Fprintf(w, "<html>Hello %s</html>", name)
	})

	mux.HandleFunc("/lfi", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if regexpPasswd.MatchString(file) {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
			return
		}
		fmt.Fprintf(w, "file=%s", file)
	})

	mux.HandleFunc("/cmd", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if m := regexpSleep.FindStringSubmatch(host); m != nil {
			secs, _ := strconv.Atoi(m[1])
			time.Sleep(time.Duration(secs) * time.Second)
		}
		fmt.Fprint(w, "pinging "+host)
	})

	return httptest.NewServer(mux)
}

var (
	regexpQuote  = regexp.MustCompile(`'`)
	regexpPasswd = regexp.MustCompile(`etc/passwd`)
	regexpSleep  = regexp.MustCompile(`sleep (\d+)`)
)

func newService(t *testing.T) (*scan.Service, ulid.ULID) {
	t.Helper()

	opts := scan.DefaultOptions()
	opts.RequestTimeout = 10 * time.Second

	svc := scan.NewService(scan.Config{
		Repository: newMemRepo(),
		Options:    opts,
	})

	entropy := ulid.Monotonic(timeReader{}, 0)
	pid := ulid.MustNew(ulid.Now(), entropy)

	return svc, pid
}

type timeReader struct{}

func (timeReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i * 7)
	}
	return len(p), nil
}

func baseGET(t *testing.T, rawURL string) *scan.RequestTemplate {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return scan.NewRequestTemplate(http.MethodGet, u, "HTTP/1.1", http.Header{}, nil)
}

func hasCheck(issues []scan.Issue, checkID string) bool {
	for _, iss := range issues {
		if iss.CheckID == checkID {
			return true
		}
	}
	return false
}

func TestActiveChecks(t *testing.T) {
	srv := vulnerableServer()
	defer srv.Close()

	// Speed up the time-based command injection check.
	old := scan.CmdInjectionDelaySeconds
	scan.CmdInjectionDelaySeconds = 2
	defer func() { scan.CmdInjectionDelaySeconds = old }()

	cases := []struct {
		name    string
		path    string
		checkID string
	}{
		{"reflected XSS", "/reflect?q=hi", "xss-reflected"},
		{"error-based SQLi", "/sqli?id=1", "sqli-error"},
		{"open redirect", "/redirect?url=/home", "open-redirect"},
		{"SSTI", "/ssti?name=bob", "ssti"},
		{"path traversal", "/lfi?file=readme.txt", "path-traversal"},
		{"command injection", "/cmd?host=127.0.0.1", "cmdi-time"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			svc, pid := newService(t)
			base := baseGET(t, srv.URL+tc.path)

			res, err := svc.ScanRequest(context.Background(), pid, base)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}

			if !hasCheck(res.Issues, tc.checkID) {
				t.Fatalf("expected check %q to fire; got issues: %s", tc.checkID, issueIDs(res.Issues))
			}
		})
	}
}

func TestPassiveChecks(t *testing.T) {
	srv := vulnerableServer()
	defer srv.Close()

	svc, pid := newService(t)
	base := baseGET(t, srv.URL+"/reflect?q=hi")

	res, err := svc.ScanRequest(context.Background(), pid, base)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if !hasCheck(res.Issues, "missing-security-headers") {
		t.Errorf("expected missing-security-headers issue; got %s", issueIDs(res.Issues))
	}
	if !hasCheck(res.Issues, "server-banner") {
		t.Errorf("expected server-banner issue; got %s", issueIDs(res.Issues))
	}
}

func TestDeduplication(t *testing.T) {
	srv := vulnerableServer()
	defer srv.Close()

	svc, pid := newService(t)
	base := baseGET(t, srv.URL+"/reflect?q=hi")

	if _, err := svc.ScanRequest(context.Background(), pid, base); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	if _, err := svc.ScanRequest(context.Background(), pid, base); err != nil {
		t.Fatalf("scan 2: %v", err)
	}

	all, err := svc.FindIssues(context.Background(), pid)
	if err != nil {
		t.Fatalf("find: %v", err)
	}

	seen := map[string]int{}
	for _, iss := range all {
		seen[iss.Fingerprint]++
	}
	for fp, n := range seen {
		if n > 1 {
			t.Errorf("issue fingerprint %q stored %d times (want 1)", fp, n)
		}
	}
}

func issueIDs(issues []scan.Issue) string {
	var b []string
	for _, iss := range issues {
		b = append(b, iss.CheckID)
	}
	return fmt.Sprintf("%v", b)
}
