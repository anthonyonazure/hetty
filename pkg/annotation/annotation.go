// Package annotation stores per-request triage metadata — a color tag and a
// free-text note — keyed by an opaque target ID (typically a request-log ULID).
// It is the lightweight equivalent of Burp's highlight colors and comments,
// letting a tester mark interesting traffic while working a target. The store is
// in-memory and project-scoped by the caller.
package annotation

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Color is a highlight color. The empty string means "no highlight".
type Color string

// Recognized highlight colors (matching common proxy palettes).
var ValidColors = map[Color]bool{
	"":       true,
	"red":    true,
	"orange": true,
	"yellow": true,
	"green":  true,
	"cyan":   true,
	"blue":   true,
	"purple": true,
	"pink":   true,
	"gray":   true,
}

// Annotation is triage metadata for one target.
type Annotation struct {
	TargetID  string    `json:"targetId"`
	Color     Color     `json:"color"`
	Note      string    `json:"note"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Store holds annotations keyed by target ID.
type Store struct {
	mu  sync.RWMutex
	now func() time.Time
	m   map[string]Annotation
}

// New returns an empty annotation store.
func New() *Store {
	return &Store{
		now: time.Now,
		m:   make(map[string]Annotation),
	}
}

// Set stores or updates an annotation. Setting an annotation with an empty
// color and empty note removes it. An unrecognized color is rejected.
func (s *Store) Set(a Annotation) (Annotation, error) {
	if a.TargetID == "" {
		return Annotation{}, fmt.Errorf("annotation: target ID required")
	}
	if !ValidColors[a.Color] {
		return Annotation{}, fmt.Errorf("annotation: invalid color %q", a.Color)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if a.Color == "" && a.Note == "" {
		delete(s.m, a.TargetID)
		return a, nil
	}

	a.UpdatedAt = s.now().UTC()
	s.m[a.TargetID] = a
	return a, nil
}

// Get returns the annotation for a target.
func (s *Store) Get(targetID string) (Annotation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.m[targetID]
	return a, ok
}

// All returns every annotation, newest first.
func (s *Store) All() []Annotation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Annotation, 0, len(s.m))
	for _, a := range s.m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	return out
}

// Delete removes a target's annotation.
func (s *Store) Delete(targetID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, targetID)
}

// Snapshot serializes the store for persistence.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.m)
}

// Restore loads annotations from a snapshot, preserving their timestamps.
func (s *Store) Restore(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var m map[string]Annotation
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = m
	return nil
}
