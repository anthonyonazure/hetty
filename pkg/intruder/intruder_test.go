package intruder_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/dstotijn/hetty/pkg/intruder"
)

// echoServer reflects the query parameters and counts requests.
func echoServer(counter *int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(counter, 1)
		a := r.URL.Query().Get("a")
		b := r.URL.Query().Get("b")
		fmt.Fprintf(w, "a=%s b=%s", a, b)
		if a == "winner" {
			fmt.Fprint(w, " FOUND-TOKEN")
		}
	}))
}

func TestCountPositions(t *testing.T) {
	base := intruder.RequestSpec{
		Method: "GET",
		URL:    "https://example.com/?a=§x§&b=§y§",
	}
	if n := intruder.CountPositions(base, ""); n != 2 {
		t.Errorf("CountPositions = %d, want 2", n)
	}
}

func TestSniperAttack(t *testing.T) {
	var counter int64
	srv := echoServer(&counter)
	defer srv.Close()

	base := intruder.RequestSpec{
		Method: "GET",
		URL:    srv.URL + "/?a=§seed§&b=§seed§",
	}

	att := intruder.Attack{
		Type:        intruder.Sniper,
		Base:        base,
		PayloadSets: [][]string{{"winner", "other"}},
		GrepMatch:   []string{"FOUND-TOKEN"},
		Concurrency: 4,
	}

	summary, results, err := intruder.NewEngine().Run(context.Background(), att)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if summary.Requests != 4 {
		t.Errorf("requests = %d, want 4", summary.Requests)
	}
	if len(results) != 4 {
		t.Fatalf("results = %d, want 4", len(results))
	}

	matched := false
	for _, r := range results {
		if r.Matches["FOUND-TOKEN"] {
			matched = true
		}
	}
	if !matched {
		t.Error("expected a result to match FOUND-TOKEN")
	}
}

func TestBatteringRam(t *testing.T) {
	var counter int64
	srv := echoServer(&counter)
	defer srv.Close()

	base := intruder.RequestSpec{Method: "GET", URL: srv.URL + "/?a=§s§&b=§s§"}
	att := intruder.Attack{
		Type:        intruder.BatteringRam,
		Base:        base,
		PayloadSets: [][]string{{"x", "y", "z"}},
	}

	summary, _, err := intruder.NewEngine().Run(context.Background(), att)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if summary.Requests != 3 {
		t.Errorf("battering ram requests = %d, want 3 (one per payload)", summary.Requests)
	}
}

func TestPitchfork(t *testing.T) {
	var counter int64
	srv := echoServer(&counter)
	defer srv.Close()

	base := intruder.RequestSpec{Method: "GET", URL: srv.URL + "/?a=§p1§&b=§p2§"}
	att := intruder.Attack{
		Type: intruder.Pitchfork,
		Base: base,
		PayloadSets: [][]string{
			{"a1", "a2", "a3"},
			{"b1", "b2"},
		},
	}

	summary, results, err := intruder.NewEngine().Run(context.Background(), att)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if summary.Requests != 2 {
		t.Errorf("pitchfork requests = %d, want 2", summary.Requests)
	}
	if len(results[0].Payloads) != 2 {
		t.Errorf("pitchfork payloads per result = %d, want 2", len(results[0].Payloads))
	}
}

func TestClusterBomb(t *testing.T) {
	var counter int64
	srv := echoServer(&counter)
	defer srv.Close()

	base := intruder.RequestSpec{Method: "GET", URL: srv.URL + "/?a=§p1§&b=§p2§"}
	att := intruder.Attack{
		Type: intruder.ClusterBomb,
		Base: base,
		PayloadSets: [][]string{
			{"a1", "a2", "a3"},
			{"b1", "b2"},
		},
	}

	summary, _, err := intruder.NewEngine().Run(context.Background(), att)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if summary.Requests != 6 {
		t.Errorf("cluster bomb requests = %d, want 6", summary.Requests)
	}
}

func TestPayloadProcessors(t *testing.T) {
	var counter int64
	srv := echoServer(&counter)
	defer srv.Close()

	base := intruder.RequestSpec{Method: "GET", URL: srv.URL + "/?a=§x§&b=fixed"}
	att := intruder.Attack{
		Type:        intruder.Sniper,
		Base:        base,
		PayloadSets: [][]string{{"hello"}},
		Processors:  []string{"upper", "suffix:!"},
		GrepExtract: `a=([^ ]+)`,
	}

	_, results, err := intruder.NewEngine().Run(context.Background(), att)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	found := false
	for _, r := range results {
		if r.Extract == "HELLO%21" || r.Extract == "HELLO!" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected processed payload in extract; got %+v", results)
	}
}

func TestNoPositionsError(t *testing.T) {
	base := intruder.RequestSpec{Method: "GET", URL: "https://example.com/no-markers"}
	att := intruder.Attack{Type: intruder.Sniper, Base: base, PayloadSets: [][]string{{"x"}}}

	if _, _, err := intruder.NewEngine().Run(context.Background(), att); err == nil {
		t.Error("expected error when no positions are marked")
	}
}
