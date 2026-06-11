package sessionflow

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// Store holds named macros and persists them via Snapshot/Restore.
type Store struct {
	mu     sync.RWMutex
	macros map[string]Macro
}

// NewStore returns an empty macro store.
func NewStore() *Store {
	return &Store{macros: map[string]Macro{}}
}

// Set adds or replaces a macro (keyed by Name).
func (s *Store) Set(m Macro) error {
	if m.Name == "" {
		return fmt.Errorf("sessionflow: macro name is required")
	}
	if len(m.Steps) == 0 {
		return fmt.Errorf("sessionflow: macro %q needs at least one step", m.Name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.macros[m.Name] = m
	return nil
}

// Get returns the macro with the given name.
func (s *Store) Get(name string) (Macro, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.macros[name]
	return m, ok
}

// List returns all macros, sorted by name.
func (s *Store) List() []Macro {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Macro, 0, len(s.macros))
	for _, m := range s.macros {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Delete removes a macro by name.
func (s *Store) Delete(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.macros, name)
}

// Snapshot serializes all macros.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.macros)
}

// Restore replaces the store contents from a snapshot.
func (s *Store) Restore(data []byte) error {
	var m map[string]Macro
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m == nil {
		m = map[string]Macro{}
	}
	s.mu.Lock()
	s.macros = m
	s.mu.Unlock()
	return nil
}
