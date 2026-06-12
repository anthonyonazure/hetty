// Package workflow chains tools into a named, repeatable sequence (the way you
// actually run an engagement): recon → probe → scan. Each step runs against the
// workflow target via an injectable step runner, so the engine stays decoupled
// from the concrete tools. Ships with common prebuilt chains and supports
// user-defined ones; results aggregate into a single report.
package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// Step is one stage of a workflow.
type Step struct {
	// Type is "native" (a built-in engine: subdomains, portscan, fingerprint,
	// tlsscan, wafdetect, webscan, screenshot) or "tool" (an external tool by
	// name from the exttool catalog).
	Type  string `json:"type"`
	Name  string `json:"name"`
	Extra string `json:"extra,omitempty"`
}

// Workflow is a named ordered chain of steps.
type Workflow struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Steps       []Step `json:"steps"`
	Builtin     bool   `json:"builtin,omitempty"`
}

// StepResult is the outcome of one step.
type StepResult struct {
	Step     Step   `json:"step"`
	Output   string `json:"output"`
	Status   string `json:"status"` // ok | error | skipped
	Detail   string `json:"detail,omitempty"`
	Duration int64  `json:"durationMs"`
}

// Result is a whole workflow run.
type Result struct {
	Workflow string       `json:"workflow"`
	Target   string       `json:"target"`
	Steps    []StepResult `json:"steps"`
}

// StepRunner executes a single step against a target and returns its text output.
type StepRunner func(ctx context.Context, target string, step Step) (string, error)

// Engine runs workflows.
type Engine struct {
	runner StepRunner
}

// New returns an engine bound to a step runner.
func New(runner StepRunner) *Engine { return &Engine{runner: runner} }

// Run executes wf against target, running every step (a failing step is recorded
// and the chain continues).
func (e *Engine) Run(ctx context.Context, wf Workflow, target string) Result {
	res := Result{Workflow: wf.Name, Target: target}
	for _, step := range wf.Steps {
		if ctx.Err() != nil {
			res.Steps = append(res.Steps, StepResult{Step: step, Status: "skipped", Detail: "aborted"})
			continue
		}
		out, err := e.runner(ctx, target, step)
		sr := StepResult{Step: step, Output: out, Status: "ok"}
		if err != nil {
			sr.Status = "error"
			sr.Detail = err.Error()
		}
		res.Steps = append(res.Steps, sr)
	}
	return res
}

// --- Store -----------------------------------------------------------------

// Store holds user workflows and serves the prebuilt ones.
type Store struct {
	mu   sync.RWMutex
	user map[string]Workflow
}

// NewStore returns a store seeded with the built-in workflows.
func NewStore() *Store { return &Store{user: map[string]Workflow{}} }

// Set adds or updates a user workflow.
func (s *Store) Set(wf Workflow) error {
	if wf.Name == "" {
		return fmt.Errorf("workflow: name is required")
	}
	if len(wf.Steps) == 0 {
		return fmt.Errorf("workflow: %q needs at least one step", wf.Name)
	}
	wf.Builtin = false
	s.mu.Lock()
	s.user[wf.Name] = wf
	s.mu.Unlock()
	return nil
}

// Get returns a workflow by name (user workflows shadow built-ins).
func (s *Store) Get(name string) (Workflow, bool) {
	s.mu.RLock()
	wf, ok := s.user[name]
	s.mu.RUnlock()
	if ok {
		return wf, true
	}
	for _, b := range builtinWorkflows {
		if b.Name == name {
			return b, true
		}
	}
	return Workflow{}, false
}

// List returns built-in + user workflows, sorted (built-ins first).
func (s *Store) List() []Workflow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]Workflow{}, builtinWorkflows...)
	for _, wf := range s.user {
		out = append(out, wf)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Builtin != out[j].Builtin {
			return out[i].Builtin
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Delete removes a user workflow.
func (s *Store) Delete(name string) {
	s.mu.Lock()
	delete(s.user, name)
	s.mu.Unlock()
}

// Snapshot/Restore persist user workflows only.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.user)
}

func (s *Store) Restore(data []byte) error {
	var m map[string]Workflow
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m == nil {
		m = map[string]Workflow{}
	}
	s.mu.Lock()
	s.user = m
	s.mu.Unlock()
	return nil
}
