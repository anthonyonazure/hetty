package monitor

import (
	"encoding/json"
	"time"
)

// Engine runs schedules: it executes a probe, diffs against the previous
// snapshot, records the result, and alerts/saves on change.
type Engine struct {
	store  *Store
	prober Prober
	alert  AlertFunc
	save   SaveFunc
}

// New returns a monitor engine. alert may be nil.
func New(store *Store, prober Prober, alert AlertFunc) *Engine {
	return &Engine{store: store, prober: prober, alert: alert}
}

// SetSaver installs the per-run snapshot saver (e.g. write to a vault dest).
func (e *Engine) SetSaver(s SaveFunc) { e.save = s }

// RunNow executes a schedule immediately and returns the diff. The first run of
// a schedule only establishes a baseline (no alert).
func (e *Engine) RunNow(id string, now time.Time) (Diff, error) {
	sc, ok := e.store.Get(id)
	if !ok {
		return Diff{}, errUnknown(id)
	}

	items, err := e.prober(*sc)
	if err != nil {
		// Still advance the timer so a flaky probe doesn't hot-loop.
		e.advance(sc, now)
		return Diff{}, err
	}

	prev := e.store.latestItems(id)
	d := computeDiff(prev, items)
	d.ScheduleID = id
	d.Time = formatTime(now)

	firstRun := len(prev) == 0 && e.store.diffsCount(id) == 0
	e.store.record(id, items, d, !firstRun)
	e.advance(sc, now)

	if !firstRun && !d.empty() && sc.AlertURL != "" && e.alert != nil {
		e.alert(*sc, d)
	}

	if sc.SaveTo != "" && e.save != nil {
		snap := RunSnapshot{
			Schedule: sc.Name, Target: sc.Target, Kind: sc.Kind, Time: d.Time,
			Items: items, Added: d.Added, Removed: d.Removed,
		}
		if blob, err := json.Marshal(snap); err == nil {
			e.save(*sc, blob)
		}
	}
	return d, nil
}

// Tick runs every schedule that is due at now.
func (e *Engine) Tick(now time.Time) {
	for _, sc := range e.store.List() {
		if !sc.Enabled {
			continue
		}
		if due(sc, now) {
			_, _ = e.RunNow(sc.ID, now)
		}
	}
}

func (e *Engine) advance(sc *Schedule, now time.Time) {
	sc.LastRun = formatTime(now)
	sc.NextRun = formatTime(now.Add(time.Duration(sc.IntervalSec) * time.Second))
}

func due(sc *Schedule, now time.Time) bool {
	if sc.NextRun == "" {
		return true
	}
	next, err := time.Parse(time.RFC3339, sc.NextRun)
	if err != nil {
		return true
	}
	return !now.Before(next)
}

func (s *Store) diffsCount(id string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.diffs[id])
}

type unknownErr string

func (u unknownErr) Error() string { return "monitor: unknown schedule " + string(u) }
func errUnknown(id string) error   { return unknownErr(id) }
