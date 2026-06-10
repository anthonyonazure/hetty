package paramminer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// target that "knows" the hidden param "debug": when present it reflects the
// value and changes the page; otherwise a stable baseline.
func minerTarget() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if v := r.Form.Get("debug"); v != "" {
			fmt.Fprintf(w, "<html>debug mode enabled token=%s extra diagnostic output here</html>", v)
			return
		}
		fmt.Fprint(w, "<html>normal page</html>")
	}))
}

func TestMineFindsReflectedParam(t *testing.T) {
	srv := minerTarget()
	defer srv.Close()

	e := New()
	res, err := e.Mine(context.Background(), srv.URL+"/", Options{
		Location:    LocationQuery,
		Wordlist:    []string{"debug", "nope1", "nope2", "nope3"},
		Concurrency: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	var found *Finding
	for i := range res.Findings {
		if res.Findings[i].Param == "debug" {
			found = &res.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("did not discover 'debug' param; findings=%+v", res.Findings)
	}
	if found.Reason != "canary reflected" {
		t.Errorf("expected reflection reason, got %q", found.Reason)
	}
	// The non-existent params must not be flagged.
	for _, f := range res.Findings {
		if f.Param != "debug" {
			t.Errorf("false positive: %s (%s)", f.Param, f.Reason)
		}
	}
}

func TestMineBodyLocation(t *testing.T) {
	srv := minerTarget()
	defer srv.Close()

	e := New()
	res, err := e.Mine(context.Background(), srv.URL+"/", Options{
		Location:    LocationBody,
		Wordlist:    []string{"debug", "missing"},
		Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Param == "debug" {
			found = true
		}
	}
	if !found {
		t.Errorf("body-location mining did not find 'debug'; findings=%+v", res.Findings)
	}
}

func TestMineInvalidTarget(t *testing.T) {
	e := New()
	if _, err := e.Mine(context.Background(), "/relative", Options{}); err == nil {
		t.Error("expected error for relative target")
	}
}
