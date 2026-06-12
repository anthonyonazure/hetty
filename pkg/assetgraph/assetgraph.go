// Package assetgraph is the unified, normalized store that every tool feeds:
// domains, hosts, URLs, services, and findings, each with first-seen/last-seen
// timestamps, the sources that observed them, free-form attributes, and parent
// relationships. Instead of each tool producing a siloed snapshot, everything
// correlates into one queryable graph that grows over time.
package assetgraph

import (
	"encoding/json"
	"sort"
	"sync"
)

// Kind is an asset type.
type Kind string

const (
	KindDomain  Kind = "domain"
	KindHost    Kind = "host"
	KindURL     Kind = "url"
	KindService Kind = "service"
	KindFinding Kind = "finding"
)

// Asset is one node in the graph.
type Asset struct {
	Key       string            `json:"key"`   // unique, e.g. "service:1.2.3.4:443"
	Kind      Kind              `json:"kind"`
	Value     string            `json:"value"` // display value
	FirstSeen string            `json:"firstSeen"`
	LastSeen  string            `json:"lastSeen"`
	Sources   []string          `json:"sources"`          // tools/scans that observed it
	Attrs     map[string]string `json:"attrs,omitempty"`  // e.g. severity, banner, technologies
	Parents   []string          `json:"parents,omitempty"` // keys of parent assets
}

// Graph is the in-memory asset store.
type Graph struct {
	mu     sync.RWMutex
	assets map[string]*Asset
}

// New returns an empty graph.
func New() *Graph { return &Graph{assets: map[string]*Asset{}} }

// Upsert merges an observation into the graph. For a new key it sets FirstSeen;
// for an existing key it bumps LastSeen and unions sources/attrs/parents. now is
// an RFC3339 timestamp supplied by the caller.
func (g *Graph) Upsert(a Asset, now string) *Asset {
	g.mu.Lock()
	defer g.mu.Unlock()

	existing, ok := g.assets[a.Key]
	if !ok {
		if a.Attrs == nil {
			a.Attrs = map[string]string{}
		}
		a.FirstSeen = now
		a.LastSeen = now
		cp := a
		g.assets[a.Key] = &cp
		return &cp
	}

	existing.LastSeen = now
	if a.Value != "" {
		existing.Value = a.Value
	}
	existing.Sources = union(existing.Sources, a.Sources)
	existing.Parents = union(existing.Parents, a.Parents)
	if existing.Attrs == nil {
		existing.Attrs = map[string]string{}
	}
	for k, v := range a.Attrs {
		existing.Attrs[k] = v
	}
	return existing
}

// Get returns an asset by key.
func (g *Graph) Get(key string) (*Asset, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	a, ok := g.assets[key]
	return a, ok
}

// List returns assets of a kind (empty kind = all), sorted by value.
func (g *Graph) List(kind Kind) []*Asset {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []*Asset
	for _, a := range g.assets {
		if kind == "" || a.Kind == kind {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

// Related returns the parents and children of an asset.
func (g *Graph) Related(key string) []*Asset {
	g.mu.RLock()
	defer g.mu.RUnlock()
	seen := map[string]bool{}
	var out []*Asset

	if a, ok := g.assets[key]; ok {
		for _, p := range a.Parents {
			if pa, ok := g.assets[p]; ok && !seen[p] {
				seen[p] = true
				out = append(out, pa)
			}
		}
	}
	for _, a := range g.assets {
		for _, p := range a.Parents {
			if p == key && !seen[a.Key] {
				seen[a.Key] = true
				out = append(out, a)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

// Stats returns counts per kind.
func (g *Graph) Stats() map[string]int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	stats := map[string]int{}
	for _, a := range g.assets {
		stats[string(a.Kind)]++
	}
	stats["total"] = len(g.assets)
	return stats
}

// Clear empties the graph.
func (g *Graph) Clear() {
	g.mu.Lock()
	g.assets = map[string]*Asset{}
	g.mu.Unlock()
}

// Snapshot/Restore persist the graph.
func (g *Graph) Snapshot() ([]byte, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return json.Marshal(g.assets)
}

func (g *Graph) Restore(data []byte) error {
	var m map[string]*Asset
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m == nil {
		m = map[string]*Asset{}
	}
	g.mu.Lock()
	g.assets = m
	g.mu.Unlock()
	return nil
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
