package workflow

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestRunChainContinuesOnError(t *testing.T) {
	runner := func(_ context.Context, target string, step Step) (string, error) {
		if step.Name == "boom" {
			return "", fmt.Errorf("kaboom")
		}
		return fmt.Sprintf("%s ran on %s", step.Name, target), nil
	}
	eng := New(runner)
	wf := Workflow{Name: "t", Steps: []Step{
		{Type: "native", Name: "a"},
		{Type: "tool", Name: "boom"},
		{Type: "native", Name: "c"},
	}}

	res := eng.Run(context.Background(), wf, "example.com")
	if len(res.Steps) != 3 {
		t.Fatalf("expected 3 step results, got %d", len(res.Steps))
	}
	if res.Steps[0].Status != "ok" || !strings.Contains(res.Steps[0].Output, "example.com") {
		t.Errorf("step a: %+v", res.Steps[0])
	}
	if res.Steps[1].Status != "error" {
		t.Errorf("step boom should error, got %s", res.Steps[1].Status)
	}
	if res.Steps[2].Status != "ok" {
		t.Errorf("chain should continue after error, step c = %s", res.Steps[2].Status)
	}
}

func TestBuiltinsAndUserStore(t *testing.T) {
	s := NewStore()
	if len(s.List()) < 5 {
		t.Fatalf("expected built-in workflows, got %d", len(s.List()))
	}
	if _, ok := s.Get("Quick recon"); !ok {
		t.Error("expected built-in 'Quick recon'")
	}

	if err := s.Set(Workflow{Name: "Mine", Steps: []Step{{Type: "tool", Name: "nmap"}}}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	wf, ok := s.Get("Mine")
	if !ok || wf.Builtin {
		t.Errorf("user workflow wrong: %+v", wf)
	}

	if err := s.Set(Workflow{Name: "bad"}); err == nil {
		t.Error("workflow with no steps should error")
	}
}

func TestStoreSnapshotRestore(t *testing.T) {
	s := NewStore()
	s.Set(Workflow{Name: "Mine", Steps: []Step{{Type: "tool", Name: "nmap"}}})
	blob, _ := s.Snapshot()

	s2 := NewStore()
	if err := s2.Restore(blob); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, ok := s2.Get("Mine"); !ok {
		t.Error("user workflow not restored")
	}
	// Built-ins still present after restore.
	if _, ok := s2.Get("Quick recon"); !ok {
		t.Error("built-ins should survive restore")
	}
}
