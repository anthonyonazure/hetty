// Package exttool runs external command-line security tools (the classic Kali /
// Sn1per arsenal) when they are installed on the host. It detects availability
// on PATH, builds argv safely (no shell, so no metacharacter injection),
// executes in the background, and captures live output for the GUI. This is the
// hybrid escape hatch: Hetty's native engines are the fast path, and these
// wrappers add depth when the real tools are present.
package exttool

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Tool is an external command definition.
type Tool struct {
	Name        string   `json:"name"`        // stable id, e.g. "nmap"
	Binary      string   `json:"binary"`      // executable looked up on PATH
	Category    string   `json:"category"`    // portscan|web|subdomain|osint|tls|brute|vuln|dns|smb|screenshot|exploit|info
	Description string   `json:"description"`
	Args        []string `json:"args"`        // argv template; {target} is substituted, extra args appended
	NeedsTarget bool     `json:"needsTarget"` // whether a target value is required
}

// Info is a tool plus its detected availability.
type Info struct {
	Tool
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
}

// Catalog holds the registered tools.
type Catalog struct {
	tools []Tool
}

// DefaultCatalog returns the built-in arsenal.
func DefaultCatalog() *Catalog {
	return &Catalog{tools: builtinTools}
}

// Tools returns the registered tool definitions.
func (c *Catalog) Tools() []Tool { return c.tools }

// Get returns a tool by name.
func (c *Catalog) Get(name string) (Tool, bool) {
	for _, t := range c.tools {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// List returns every tool with its current availability.
func (c *Catalog) List() []Info {
	out := make([]Info, 0, len(c.tools))
	for _, t := range c.tools {
		path, ok := lookPath(t.Binary)
		out = append(out, Info{Tool: t, Available: ok, Path: path})
	}
	return out
}

// lookPath is overridable in tests.
var lookPath = func(binary string) (string, bool) {
	p, err := exec.LookPath(binary)
	if err != nil {
		return "", false
	}
	return p, true
}

// buildArgs renders a tool's argv template against target plus extra args.
// Extra is split on whitespace into separate argv elements (no shell).
func buildArgs(t Tool, target, extra string) []string {
	var args []string
	for _, a := range t.Args {
		args = append(args, strings.ReplaceAll(a, "{target}", target))
	}
	for _, e := range strings.Fields(extra) {
		args = append(args, e)
	}
	return args
}

// Job is a running or finished tool execution.
type Job struct {
	ID         string `json:"id"`
	Tool       string `json:"tool"`
	Target     string `json:"target"`
	Cmdline    string `json:"cmdline"`
	Status     string `json:"status"` // running | done | failed
	ExitCode   int    `json:"exitCode"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt,omitempty"`

	mu     sync.Mutex
	output strings.Builder
	cancel context.CancelFunc
}

// Output returns the captured output so far.
func (j *Job) Output() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.output.String()
}

func (j *Job) write(p []byte) {
	j.mu.Lock()
	j.output.Write(p)
	j.mu.Unlock()
}

func (j *Job) setStatus(status string, code int) {
	j.mu.Lock()
	j.Status = status
	j.ExitCode = code
	j.mu.Unlock()
}

// jobView is the JSON-serializable snapshot of a job.
type jobView struct {
	ID         string `json:"id"`
	Tool       string `json:"tool"`
	Target     string `json:"target"`
	Cmdline    string `json:"cmdline"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exitCode"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt,omitempty"`
	Output     string `json:"output"`
}

// View returns a serializable snapshot.
func (j *Job) View() jobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	return jobView{
		ID: j.ID, Tool: j.Tool, Target: j.Target, Cmdline: j.Cmdline,
		Status: j.Status, ExitCode: j.ExitCode, StartedAt: j.StartedAt,
		FinishedAt: j.FinishedAt, Output: j.output.String(),
	}
}

// Runner executes catalog tools as background jobs.
type Runner struct {
	catalog *Catalog
	timeout time.Duration

	mu   sync.Mutex
	jobs map[string]*Job
	seq  int
}

// NewRunner returns a runner. timeout bounds each job (default 15m).
func NewRunner(catalog *Catalog, timeout time.Duration) *Runner {
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	return &Runner{catalog: catalog, timeout: timeout, jobs: map[string]*Job{}}
}

// Catalog returns the runner's tool catalog.
func (r *Runner) Catalog() *Catalog { return r.catalog }

// Start launches toolName against target (with optional extra args) and returns
// the job immediately. The job runs in the background.
func (r *Runner) Start(parent context.Context, toolName, target, extra string) (*Job, error) {
	tool, ok := r.catalog.Get(toolName)
	if !ok {
		return nil, fmt.Errorf("exttool: unknown tool %q", toolName)
	}
	if tool.NeedsTarget && strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("exttool: %s requires a target", toolName)
	}
	path, ok := lookPath(tool.Binary)
	if !ok {
		return nil, fmt.Errorf("exttool: %q is not installed (binary %q not found on PATH)", toolName, tool.Binary)
	}

	args := buildArgs(tool, target, extra)

	r.mu.Lock()
	r.seq++
	id := fmt.Sprintf("job-%d", r.seq)
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	job := &Job{
		ID:        id,
		Tool:      toolName,
		Target:    target,
		Cmdline:   tool.Binary + " " + strings.Join(args, " "),
		Status:    "running",
		StartedAt: now(),
		cancel:    cancel,
	}

	r.mu.Lock()
	r.jobs[id] = job
	r.mu.Unlock()

	go func() {
		defer cancel()
		cmd := exec.CommandContext(ctx, path, args...)
		w := &jobWriter{job: job}
		cmd.Stdout = w
		cmd.Stderr = w

		err := cmd.Run()
		code := 0
		status := "done"
		if err != nil {
			status = "failed"
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				code = -1
				job.write([]byte("\n[exttool] " + err.Error() + "\n"))
			}
		}
		job.setStatus(status, code)
		job.mu.Lock()
		job.FinishedAt = now()
		job.mu.Unlock()
	}()

	return job, nil
}

// Job returns a job by id.
func (r *Runner) Job(id string) (*Job, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[id]
	return j, ok
}

// Jobs returns all jobs, newest first.
func (r *Runner) Jobs() []*Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Job, 0, len(r.jobs))
	for _, j := range r.jobs {
		out = append(out, j)
	}
	// Newest first by sequence-encoded id length then value is unreliable;
	// callers mostly poll by id, so ordering here is best-effort.
	return out
}

// Stop cancels a running job.
func (r *Runner) Stop(id string) bool {
	r.mu.Lock()
	j, ok := r.jobs[id]
	r.mu.Unlock()
	if !ok {
		return false
	}
	if j.cancel != nil {
		j.cancel()
	}
	return true
}

type jobWriter struct{ job *Job }

func (w *jobWriter) Write(p []byte) (int, error) {
	w.job.write(p)
	return len(p), nil
}

// now is overridable in tests.
var now = func() string { return time.Now().UTC().Format(time.RFC3339) }
