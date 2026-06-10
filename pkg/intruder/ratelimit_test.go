package intruder

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dstotijn/hetty/pkg/ratelimit"
)

func TestAttackRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	e := NewEngine()
	attack := Attack{
		Type:              Sniper,
		Base:              RequestSpec{Method: "GET", URL: srv.URL + "/?a=@@p@@"},
		Marker:            "@@",
		PayloadSets:       [][]string{{"1", "2", "3", "4"}},
		RequestsPerSecond: 25, // 40ms min interval
		Concurrency:       4,
	}

	start := time.Now()
	_, results, err := e.Run(context.Background(), attack)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 4 {
		t.Fatalf("results = %d, want 4", len(results))
	}
	for _, r := range results {
		if r.Error != "" {
			t.Fatalf("request error: %s", r.Error)
		}
	}

	// 4 requests at 40ms spacing => at least ~120ms (3 gaps) despite concurrency.
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("rate limit not enforced: 4 requests took %v, want >= 100ms", elapsed)
	}
}

func TestEngineLimiterApplies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	e := NewEngine()
	e.SetLimiter(ratelimit.New(ratelimit.Config{RequestsPerSecond: 25})) // engine-wide 40ms interval

	attack := Attack{
		Type:        Sniper,
		Base:        RequestSpec{Method: "GET", URL: srv.URL + "/?a=@@p@@"},
		Marker:      "@@",
		PayloadSets: [][]string{{"1", "2", "3"}},
		Concurrency: 3,
	}

	start := time.Now()
	_, results, err := e.Run(context.Background(), attack)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Errorf("engine limiter not enforced: 3 requests took %v, want >= 60ms", elapsed)
	}
}
