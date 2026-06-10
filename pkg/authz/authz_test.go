package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dstotijn/hetty/pkg/session"
)

// adminBody is the privileged response; lowBody differs only in the username.
const adminBody = "<html><body>Account 42 balance 1000 owner admin settings panel</body></html>"

func newTarget() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie := r.Header.Get("Cookie")
		auth := r.Header.Get("Authorization")
		switch {
		case auth == "Bearer admin-token" || cookie == "sid=admin":
			// Privileged user.
			_, _ = w.Write([]byte(adminBody))
		case cookie == "sid=low":
			// Vulnerable endpoint: serves the same data to a low-priv user.
			_, _ = w.Write([]byte(adminBody))
		case cookie == "sid=enforced":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
		default:
			// Unauthenticated -> redirect to login.
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}))
}

func TestAnalyzeBypassed(t *testing.T) {
	srv := newTarget()
	defer srv.Close()

	e := NewEngine(Config{Client: srv.Client()})
	base := RequestSpec{
		Method:  "GET",
		URL:     srv.URL + "/account/42",
		Headers: []Header{{Name: "Cookie", Value: "sid=admin"}},
	}
	res, err := e.Analyze(context.Background(), base, []Identity{
		{Label: "low-priv", Profile: &session.Profile{Name: "low", Cookies: []session.Cookie{{Name: "sid", Value: "low"}}}},
		{Label: "unauth"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Identities) != 2 {
		t.Fatalf("want 2 identity results, got %d", len(res.Identities))
	}

	low := res.Identities[0]
	if low.Verdict != VerdictBypassed {
		t.Errorf("low-priv verdict = %q (%s), want bypassed", low.Verdict, low.Note)
	}

	unauth := res.Identities[1]
	if unauth.Verdict != VerdictEnforced {
		t.Errorf("unauth verdict = %q (%s), want enforced", unauth.Verdict, unauth.Note)
	}
}

func TestAnalyzeEnforced(t *testing.T) {
	srv := newTarget()
	defer srv.Close()

	e := NewEngine(Config{Client: srv.Client()})
	base := RequestSpec{
		Method:  "GET",
		URL:     srv.URL + "/account/42",
		Headers: []Header{{Name: "Cookie", Value: "sid=admin"}},
	}
	res, err := e.Analyze(context.Background(), base, []Identity{
		{Label: "blocked", Profile: &session.Profile{Name: "enf", Cookies: []session.Cookie{{Name: "sid", Value: "enforced"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := res.Identities[0].Verdict; v != VerdictEnforced {
		t.Errorf("verdict = %q (%s), want enforced", v, res.Identities[0].Note)
	}
}

func TestSimilarity(t *testing.T) {
	if s := Similarity([]byte("a b c d"), []byte("a b c d")); s != 1 {
		t.Errorf("identical similarity = %v, want 1", s)
	}
	if s := Similarity([]byte("a b c d"), []byte("w x y z")); s != 0 {
		t.Errorf("disjoint similarity = %v, want 0", s)
	}
	s := Similarity([]byte("the quick brown fox"), []byte("the quick brown cat"))
	if s <= 0.5 || s >= 1 {
		t.Errorf("partial similarity = %v, want between 0.5 and 1", s)
	}
}

func TestClassifyRedirect(t *testing.T) {
	v, _ := classify(response{status: 200}, response{status: 302}, 0, 0.95)
	if v != VerdictEnforced {
		t.Errorf("302 from 200 baseline = %q, want enforced", v)
	}
}
