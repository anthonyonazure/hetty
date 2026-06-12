// Package monitor turns Hetty's point-in-time tools into a continuous
// attack-surface monitor: schedules re-run a probe against a target on a timer,
// diff the result against the previous snapshot ("what's new since last time"),
// and fire alerts on change. This is the spine that ties the tools together
// over time — the thing that catches a new subdomain, a newly open port, or a
// freshly vulnerable service before anyone else.
package monitor

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Schedule is a recurring monitoring job.
type Schedule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Target   string `json:"target"`
	// Kind selects what to run, e.g. "portscan", "subdomains", "fingerprint",
	// "tool:nmap", "asm:recon", "workflow:<name>".
	Kind        string `json:"kind"`
	Extra       string `json:"extra,omitempty"`       // extra args for tool:* kinds
	IntervalSec int    `json:"intervalSec"`           // timer interval
	Enabled     bool   `json:"enabled"`
	AlertURL    string `json:"alertUrl,omitempty"`    // webhook/Slack URL for change alerts
	SaveTo      string `json:"saveTo,omitempty"`      // vault destination name to snapshot each run to
	LastRun     string `json:"lastRun,omitempty"`
	NextRun     string `json:"nextRun,omitempty"`
}

// Diff is the change between two consecutive snapshots.
type Diff struct {
	ScheduleID string   `json:"scheduleId"`
	Time       string   `json:"time"`
	Added      []string `json:"added"`
	Removed    []string `json:"removed"`
}

func (d Diff) empty() bool { return len(d.Added) == 0 && len(d.Removed) == 0 }

// Prober runs a schedule's probe and returns the normalized set of observed
// items (e.g. subdomains, "port:443", finding ids).
type Prober func(s Schedule) ([]string, error)

// AlertFunc delivers a change notification (e.g. POST to a webhook).
type AlertFunc func(s Schedule, d Diff)

// SaveFunc persists a run's snapshot (e.g. to a vault destination).
type SaveFunc func(s Schedule, snapshot []byte)

// Snapshot is the JSON payload saved per run when a schedule has SaveTo set.
type RunSnapshot struct {
	Schedule string   `json:"schedule"`
	Target   string   `json:"target"`
	Kind     string   `json:"kind"`
	Time     string   `json:"time"`
	Items    []string `json:"items"`
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
}

const maxDiffsPerSchedule = 50

// Store holds schedules, the latest snapshot per schedule, and recent diffs.
type Store struct {
	mu        sync.RWMutex
	schedules map[string]*Schedule
	latest    map[string][]string
	diffs     map[string][]Diff
	seq       int
}

// NewStore returns an empty monitor store.
func NewStore() *Store {
	return &Store{
		schedules: map[string]*Schedule{},
		latest:    map[string][]string{},
		diffs:     map[string][]Diff{},
	}
}

// Set adds or updates a schedule. A new schedule (empty ID) gets an assigned id.
func (s *Store) Set(sc *Schedule) (*Schedule, error) {
	if sc.Target == "" || sc.Kind == "" {
		return nil, fmt.Errorf("monitor: schedule needs target and kind")
	}
	if sc.IntervalSec < 30 {
		sc.IntervalSec = 30
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sc.ID == "" {
		s.seq++
		sc.ID = fmt.Sprintf("sched-%d", s.seq)
	}
	if sc.Name == "" {
		sc.Name = sc.Kind + " " + sc.Target
	}
	s.schedules[sc.ID] = sc
	return sc, nil
}

// Get returns a schedule by id.
func (s *Store) Get(id string) (*Schedule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.schedules[id]
	return sc, ok
}

// List returns all schedules sorted by name.
func (s *Store) List() []*Schedule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Schedule, 0, len(s.schedules))
	for _, sc := range s.schedules {
		out = append(out, sc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Delete removes a schedule and its history.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	delete(s.schedules, id)
	delete(s.latest, id)
	delete(s.diffs, id)
	s.mu.Unlock()
}

// Diffs returns the recent diffs for a schedule, newest first.
func (s *Store) Diffs(id string) []Diff {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.diffs[id]
	out := make([]Diff, len(src))
	copy(out, src)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Store) latestItems(id string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latest[id]
}

func (s *Store) record(id string, items []string, d Diff, recordDiff bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latest[id] = items
	if recordDiff && !d.empty() {
		s.diffs[id] = append(s.diffs[id], d)
		if len(s.diffs[id]) > maxDiffsPerSchedule {
			s.diffs[id] = s.diffs[id][len(s.diffs[id])-maxDiffsPerSchedule:]
		}
	}
}

type persisted struct {
	Schedules map[string]*Schedule `json:"schedules"`
	Latest    map[string][]string  `json:"latest"`
	Diffs     map[string][]Diff    `json:"diffs"`
	Seq       int                  `json:"seq"`
}

// Snapshot serializes the whole store.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(persisted{Schedules: s.schedules, Latest: s.latest, Diffs: s.diffs, Seq: s.seq})
}

// Restore replaces store contents from a snapshot.
func (s *Store) Restore(data []byte) error {
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schedules = orEmptySchedule(p.Schedules)
	s.latest = orEmptyItems(p.Latest)
	s.diffs = orEmptyDiffs(p.Diffs)
	s.seq = p.Seq
	return nil
}

func orEmptySchedule(m map[string]*Schedule) map[string]*Schedule {
	if m == nil {
		return map[string]*Schedule{}
	}
	return m
}
func orEmptyItems(m map[string][]string) map[string][]string {
	if m == nil {
		return map[string][]string{}
	}
	return m
}
func orEmptyDiffs(m map[string][]Diff) map[string][]Diff {
	if m == nil {
		return map[string][]Diff{}
	}
	return m
}

// computeDiff returns the items added/removed going from prev to cur.
func computeDiff(prev, cur []string) Diff {
	prevSet := map[string]bool{}
	for _, p := range prev {
		prevSet[p] = true
	}
	curSet := map[string]bool{}
	for _, c := range cur {
		curSet[c] = true
	}
	var added, removed []string
	for c := range curSet {
		if !prevSet[c] {
			added = append(added, c)
		}
	}
	for p := range prevSet {
		if !curSet[p] {
			removed = append(removed, p)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return Diff{Added: added, Removed: removed}
}

// formatTime is overridable in tests.
var formatTime = func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
