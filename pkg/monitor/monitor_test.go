package monitor

import (
	"testing"
	"time"
)

func TestComputeDiff(t *testing.T) {
	d := computeDiff([]string{"a", "b", "c"}, []string{"b", "c", "d"})
	if len(d.Added) != 1 || d.Added[0] != "d" {
		t.Errorf("added = %v, want [d]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "a" {
		t.Errorf("removed = %v, want [a]", d.Removed)
	}
}

func TestBaselineThenChangeAndAlert(t *testing.T) {
	store := NewStore()
	sc, _ := store.Set(&Schedule{Target: "example.com", Kind: "subdomains", IntervalSec: 60, Enabled: true, AlertURL: "http://hook"})

	// The prober returns different sets on successive calls.
	calls := 0
	results := [][]string{
		{"www.example.com", "api.example.com"},
		{"www.example.com", "api.example.com", "dev.example.com"}, // dev is NEW
	}
	prober := func(s Schedule) ([]string, error) {
		r := results[calls]
		calls++
		return r, nil
	}

	var alerts []Diff
	alert := func(s Schedule, d Diff) { alerts = append(alerts, d) }

	eng := New(store, prober, alert)
	t0 := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)

	// First run: baseline, no alert.
	d1, err := eng.RunNow(sc.ID, t0)
	if err != nil {
		t.Fatalf("run1: %v", err)
	}
	if !d1.empty() {
		// First run records the items as "added" relative to empty, but must NOT alert.
	}
	if len(alerts) != 0 {
		t.Fatalf("baseline run should not alert, got %d", len(alerts))
	}

	// Second run: dev.example.com is new -> alert.
	d2, err := eng.RunNow(sc.ID, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("run2: %v", err)
	}
	if len(d2.Added) != 1 || d2.Added[0] != "dev.example.com" {
		t.Fatalf("expected dev.example.com added, got %v", d2.Added)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	// Diffs history records the change.
	if len(store.Diffs(sc.ID)) != 1 {
		t.Errorf("expected 1 recorded diff")
	}
	// NextRun advanced.
	got, _ := store.Get(sc.ID)
	if got.NextRun == "" {
		t.Errorf("nextRun should be set")
	}
}

func TestSaveToSnapshot(t *testing.T) {
	store := NewStore()
	sc, _ := store.Set(&Schedule{Target: "x.com", Kind: "subdomains", IntervalSec: 60, SaveTo: "loot"})

	var saved [][]byte
	eng := New(store, func(s Schedule) ([]string, error) { return []string{"a", "b"}, nil }, nil)
	eng.SetSaver(func(s Schedule, snapshot []byte) { saved = append(saved, snapshot) })

	if _, err := eng.RunNow(sc.ID, time.Now()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(saved) != 1 {
		t.Fatalf("expected 1 saved snapshot, got %d", len(saved))
	}
	if !contains(string(saved[0]), "x.com") || !contains(string(saved[0]), "subdomains") {
		t.Errorf("snapshot missing fields: %s", saved[0])
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestTickDueLogic(t *testing.T) {
	store := NewStore()
	sc, _ := store.Set(&Schedule{Target: "t", Kind: "portscan", IntervalSec: 300, Enabled: true})

	ran := 0
	eng := New(store, func(s Schedule) ([]string, error) { ran++; return []string{"port:80"}, nil }, nil)

	t0 := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	eng.Tick(t0) // first tick: NextRun empty -> due -> runs
	if ran != 1 {
		t.Fatalf("first tick should run, ran=%d", ran)
	}
	eng.Tick(t0.Add(time.Minute)) // not due yet (interval 300s)
	if ran != 1 {
		t.Fatalf("should not run before interval, ran=%d", ran)
	}
	eng.Tick(t0.Add(6 * time.Minute)) // now due
	if ran != 2 {
		t.Fatalf("should run after interval, ran=%d", ran)
	}
	_ = sc
}

func TestDisabledSchedulesSkipped(t *testing.T) {
	store := NewStore()
	store.Set(&Schedule{Target: "t", Kind: "portscan", IntervalSec: 60, Enabled: false})
	ran := 0
	eng := New(store, func(s Schedule) ([]string, error) { ran++; return nil, nil }, nil)
	eng.Tick(time.Now())
	if ran != 0 {
		t.Fatal("disabled schedule should not run")
	}
}

func TestSnapshotRestore(t *testing.T) {
	store := NewStore()
	sc, _ := store.Set(&Schedule{Target: "x", Kind: "subdomains", IntervalSec: 60})
	store.record(sc.ID, []string{"a"}, Diff{ScheduleID: sc.ID, Added: []string{"a"}}, true)

	blob, err := store.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	s2 := NewStore()
	if err := s2.Restore(blob); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, ok := s2.Get(sc.ID); !ok {
		t.Error("schedule not restored")
	}
	if len(s2.latestItems(sc.ID)) != 1 {
		t.Error("latest items not restored")
	}
}
