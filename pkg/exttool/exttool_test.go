package exttool

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCatalogGetAndList(t *testing.T) {
	c := DefaultCatalog()
	if _, ok := c.Get("nmap"); !ok {
		t.Fatal("expected nmap in catalog")
	}
	if _, ok := c.Get("nope"); ok {
		t.Fatal("unexpected tool")
	}
	if len(c.List()) != len(c.Tools()) {
		t.Fatal("List/Tools length mismatch")
	}
}

func TestBuildArgsSubstitution(t *testing.T) {
	tool := Tool{Name: "x", Args: []string{"-u", "{target}", "--silent"}}
	got := buildArgs(tool, "https://h.example/", "-t 50 -o out.txt")
	want := []string{"-u", "https://h.example/", "--silent", "-t", "50", "-o", "out.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildArgs = %v, want %v", got, want)
	}
}

func TestAvailabilityDetection(t *testing.T) {
	// `go` is on PATH in the build/test environment.
	if _, ok := lookPath("go"); !ok {
		t.Skip("go not on PATH; skipping availability check")
	}
	if _, ok := lookPath("definitely-not-a-real-binary-xyz123"); ok {
		t.Fatal("nonexistent binary should not be available")
	}
}

func TestRunJobLifecycle(t *testing.T) {
	// A catalog with one tool that shells out to `go version` — deterministic,
	// available wherever the tests run.
	cat := &Catalog{tools: []Tool{
		{Name: "goversion", Binary: "go", Category: "info", Args: []string{"version"}},
	}}
	r := NewRunner(cat, 30*time.Second)

	job, err := r.Start(context.Background(), "goversion", "", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Poll for completion.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if j, _ := r.Job(job.ID); j != nil && j.View().Status != "running" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	v := job.View()
	if v.Status != "done" {
		t.Fatalf("status = %q, output: %s", v.Status, v.Output)
	}
	if !strings.Contains(v.Output, "go version") {
		t.Fatalf("expected 'go version' in output, got %q", v.Output)
	}
}

func TestStartUnknownAndMissingTarget(t *testing.T) {
	r := NewRunner(DefaultCatalog(), time.Minute)
	if _, err := r.Start(context.Background(), "no-such-tool", "x", ""); err == nil {
		t.Fatal("expected error for unknown tool")
	}
	if _, err := r.Start(context.Background(), "nmap", "", ""); err == nil {
		t.Fatal("expected error for missing target")
	}
}

func TestStartMissingBinary(t *testing.T) {
	cat := &Catalog{tools: []Tool{
		{Name: "ghost", Binary: "definitely-not-real-xyz123", NeedsTarget: true, Args: []string{"{target}"}},
	}}
	r := NewRunner(cat, time.Minute)
	if _, err := r.Start(context.Background(), "ghost", "t", ""); err == nil {
		t.Fatal("expected error for missing binary")
	}
}
