package collab_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dstotijn/hetty/pkg/collab"
)

func TestRecordsInteraction(t *testing.T) {
	s := collab.NewServer("http://placeholder")
	httpSrv := httptest.NewServer(s.Handler())
	defer httpSrv.Close()

	// Point callbacks at the real test server.
	s.SetBaseURL(httpSrv.URL)

	token, url := s.NewToken()
	if s.InteractionCount(token) != 0 {
		t.Fatalf("expected 0 interactions before callback")
	}

	res, err := http.Get(url + "/path?x=1")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	res.Body.Close()

	if got := s.InteractionCount(token); got != 1 {
		t.Fatalf("interaction count = %d, want 1", got)
	}

	inter := s.Interactions(token)
	if inter[0].Method != http.MethodGet {
		t.Errorf("method = %q, want GET", inter[0].Method)
	}
	if inter[0].Protocol != "http" {
		t.Errorf("protocol = %q, want http", inter[0].Protocol)
	}
}

func TestUnknownTokenNoInteractions(t *testing.T) {
	s := collab.NewServer("http://x")
	if s.InteractionCount("nope") != 0 {
		t.Error("unknown token should have 0 interactions")
	}
}

func TestTokensAreUnique(t *testing.T) {
	s := collab.NewServer("http://x")
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, _ := s.NewToken()
		if seen[tok] {
			t.Fatalf("duplicate token: %s", tok)
		}
		seen[tok] = true
	}
}
