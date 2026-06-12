package cluster

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestFanOutDistributesAndAggregates(t *testing.T) {
	var hitsA, hitsB int32

	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitsA, 1)
		if r.URL.Path != "/api/portscan" {
			t.Errorf("worker A unexpected path %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"host":"x","open":[{"port":80}]}`)
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitsB, 1)
		fmt.Fprint(w, `{"host":"y","open":[]}`)
	}))
	defer srvB.Close()

	workers := []Worker{{Name: "A", URL: srvA.URL}, {Name: "B", URL: srvB.URL}}
	targets := []string{"t1", "t2", "t3", "t4"}

	res, err := New().Run(context.Background(), workers, targets, "portscan")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OK != 4 || res.Failed != 0 {
		t.Fatalf("expected 4 ok, got ok=%d failed=%d", res.OK, res.Failed)
	}
	// Round-robin: 4 targets across 2 workers -> 2 each.
	if hitsA != 2 || hitsB != 2 {
		t.Errorf("uneven distribution: A=%d B=%d", hitsA, hitsB)
	}
	if len(res.Tasks) != 4 {
		t.Fatalf("expected 4 tasks")
	}
}

func TestFanOutWorkerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	res, err := New().Run(context.Background(), []Worker{{Name: "A", URL: srv.URL}}, []string{"t1"}, "portscan")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Failed != 1 || res.Tasks[0].Status != "error" {
		t.Fatalf("expected a failed task, got %+v", res)
	}
}

func TestTokenForwarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Hetty-Token") != "secret" {
			t.Errorf("worker token not forwarded")
		}
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()
	New().Run(context.Background(), []Worker{{Name: "A", URL: srv.URL, Token: "secret"}}, []string{"t1"}, "tlsscan")
}

func TestRunValidation(t *testing.T) {
	if _, err := New().Run(context.Background(), nil, []string{"t"}, "portscan"); err == nil {
		t.Error("expected error with no workers")
	}
	if _, err := New().Run(context.Background(), []Worker{{Name: "A", URL: "http://x"}}, []string{"t"}, "bogus"); err == nil {
		t.Error("expected error for unsupported kind")
	}
}

func TestStore(t *testing.T) {
	s := NewStore()
	if err := s.Set(Worker{Name: "w1", URL: "http://10.0.0.5:8080"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := s.Set(Worker{Name: "bad"}); err == nil {
		t.Error("worker without url should error")
	}
	blob, _ := s.Snapshot()
	s2 := NewStore()
	if err := s2.Restore(blob); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(s2.List()) != 1 {
		t.Error("worker not restored")
	}
}
