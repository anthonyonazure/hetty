package ext

import (
	"encoding/json"
	"sort"
	"sync"
)

// Store is the namespaced key/value store handed to extensions via
// `hetty.store`. Each extension gets its own namespace (its file name). Values
// are strings — extensions JSON-encode richer data themselves. Store implements
// Snapshot/Restore so it is persisted across restarts via the bbolt tool_state
// bucket, like the other tool stores.
type Store struct {
	mu   sync.RWMutex
	data map[string]map[string]string // namespace -> key -> value
}

// NewStore returns an empty extension store.
func NewStore() *Store {
	return &Store{data: map[string]map[string]string{}}
}

// Get returns the value for key in namespace ns.
func (s *Store) Get(ns, key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.data[ns]
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	return v, ok
}

// Set stores value under key in namespace ns.
func (s *Store) Set(ns, key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.data[ns]
	if m == nil {
		m = map[string]string{}
		s.data[ns] = m
	}
	m[key] = value
}

// Delete removes key from namespace ns.
func (s *Store) Delete(ns, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.data[ns]; m != nil {
		delete(m, key)
	}
}

// Keys returns the sorted keys in namespace ns.
func (s *Store) Keys(ns string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.data[ns]
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Snapshot serializes the whole store for persistence.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.data)
}

// Restore replaces the store contents from a snapshot.
func (s *Store) Restore(data []byte) error {
	var d map[string]map[string]string
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	if d == nil {
		d = map[string]map[string]string{}
	}
	s.mu.Lock()
	s.data = d
	s.mu.Unlock()
	return nil
}
