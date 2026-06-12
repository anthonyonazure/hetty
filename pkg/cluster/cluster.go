// Package cluster distributes scanning across multiple Hetty instances. A
// controller fans a target list out across registered worker nodes (each just a
// Hetty instance exposing its REST API), runs a scan kind on each, and
// aggregates the results — Axiom-style horizontal scaling, native and with no
// cloud-provider SDK. Provision the workers however you like (Axiom, cloud-init,
// manual); the controller only needs their URLs.
package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Worker is a remote Hetty instance the controller can dispatch to.
type Worker struct {
	Name  string `json:"name"`
	URL   string `json:"url"`             // base URL, e.g. http://10.0.0.5:8080
	Token string `json:"token,omitempty"` // optional --auth-token of the worker
}

// Task is one (worker, target) unit of work and its result.
type Task struct {
	Target string          `json:"target"`
	Worker string          `json:"worker"`
	Kind   string          `json:"kind"`
	Status string          `json:"status"` // ok | error
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Result is a whole fan-out run.
type Result struct {
	Kind    string `json:"kind"`
	Targets int    `json:"targets"`
	Workers int    `json:"workers"`
	OK      int    `json:"ok"`
	Failed  int    `json:"failed"`
	Tasks   []Task `json:"tasks"`
}

// supported kinds → the worker REST endpoint + how to build the body.
func endpointFor(kind, target string) (path string, body interface{}, ok bool) {
	switch kind {
	case "portscan":
		return "/api/portscan", map[string]interface{}{"host": target, "options": map[string]interface{}{"topPorts": 100, "banner": true}}, true
	case "subdomains":
		return "/api/recon/subdomains", map[string]interface{}{"domain": target, "options": map[string]interface{}{"concurrency": 20}}, true
	case "fingerprint":
		return "/api/recon/fingerprint", map[string]interface{}{"url": ensureURL(target)}, true
	case "tlsscan":
		return "/api/tlsscan", map[string]interface{}{"host": target}, true
	case "wafdetect":
		return "/api/wafdetect", map[string]interface{}{"url": ensureURL(target)}, true
	default:
		return "", nil, false
	}
}

// Engine runs fan-out scans.
type Engine struct {
	client *http.Client
}

// New returns a cluster engine.
func New() *Engine {
	return &Engine{client: &http.Client{Timeout: 5 * time.Minute}}
}

// Run distributes targets across workers (round-robin) and runs kind on each,
// concurrently. With no workers it returns an error result.
func (e *Engine) Run(ctx context.Context, workers []Worker, targets []string, kind string) (Result, error) {
	if len(workers) == 0 {
		return Result{}, fmt.Errorf("cluster: no workers configured")
	}
	if _, _, ok := endpointFor(kind, ""); !ok {
		return Result{}, fmt.Errorf("cluster: unsupported kind %q (portscan|subdomains|fingerprint|tlsscan|wafdetect)", kind)
	}

	res := Result{Kind: kind, Targets: len(targets), Workers: len(workers)}
	tasks := make([]Task, len(targets))

	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, len(workers)*4)
	)
	for i, target := range targets {
		worker := workers[i%len(workers)]
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, target string, worker Worker) {
			defer wg.Done()
			defer func() { <-sem }()
			tasks[idx] = e.dispatch(ctx, worker, target, kind)
		}(i, target, worker)
	}
	wg.Wait()

	for _, t := range tasks {
		if t.Status == "ok" {
			res.OK++
		} else {
			res.Failed++
		}
	}
	res.Tasks = tasks
	return res, nil
}

func (e *Engine) dispatch(ctx context.Context, worker Worker, target, kind string) Task {
	task := Task{Target: target, Worker: worker.Name, Kind: kind, Status: "error"}

	path, body, _ := endpointFor(kind, target)
	payload, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(worker.URL, "/")+path, bytes.NewReader(payload))
	if err != nil {
		task.Error = err.Error()
		return task
	}
	req.Header.Set("Content-Type", "application/json")
	if worker.Token != "" {
		req.Header.Set("X-Hetty-Token", worker.Token)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		task.Error = err.Error()
		return task
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	if resp.StatusCode/100 != 2 {
		task.Error = fmt.Sprintf("worker %s: %s", worker.Name, resp.Status)
		return task
	}
	task.Status = "ok"
	task.Result = json.RawMessage(buf.Bytes())
	return task
}

func ensureURL(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	return "https://" + s
}
