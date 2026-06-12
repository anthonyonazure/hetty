package cluster

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// Store holds registered workers and persists them.
type Store struct {
	mu      sync.RWMutex
	workers map[string]Worker
}

// NewStore returns an empty worker store.
func NewStore() *Store { return &Store{workers: map[string]Worker{}} }

// Set adds or replaces a worker.
func (s *Store) Set(w Worker) error {
	if w.Name == "" || w.URL == "" {
		return fmt.Errorf("cluster: worker needs a name and url")
	}
	s.mu.Lock()
	s.workers[w.Name] = w
	s.mu.Unlock()
	return nil
}

// List returns all workers sorted by name.
func (s *Store) List() []Worker {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Worker, 0, len(s.workers))
	for _, w := range s.workers {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Delete removes a worker.
func (s *Store) Delete(name string) {
	s.mu.Lock()
	delete(s.workers, name)
	s.mu.Unlock()
}

// Snapshot/Restore persist the workers (tokens redacted in List, kept here).
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.workers)
}

func (s *Store) Restore(data []byte) error {
	var m map[string]Worker
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m == nil {
		m = map[string]Worker{}
	}
	s.mu.Lock()
	s.workers = m
	s.mu.Unlock()
	return nil
}
