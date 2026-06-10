// Package ratelimit provides a small, shared throttle used by the scanner,
// intruder, spider and content-discovery engines so Hetty can stay within a
// target program's politeness limits and avoid getting the tester banned.
//
// A Limiter combines two independent controls:
//
//   - a request-rate cap (requests per second), enforced as a minimum interval
//     between successive acquisitions;
//   - a concurrency cap (maximum number of simultaneously in-flight requests),
//     enforced with a counting semaphore.
//
// The zero value is unlimited. A nil *Limiter is also unlimited, so callers can
// hold an optional limiter without nil checks.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter throttles request acquisition by rate and concurrency.
type Limiter struct {
	mu          sync.Mutex
	minInterval time.Duration
	next        time.Time
	sem         chan struct{}
}

// Config configures a Limiter.
type Config struct {
	// RequestsPerSecond caps the acquisition rate. Zero or negative means no
	// rate cap.
	RequestsPerSecond float64
	// MaxConcurrent caps simultaneously in-flight requests. Zero or negative
	// means no concurrency cap.
	MaxConcurrent int
}

// New returns a Limiter for the given config. A nil/zero config yields an
// unlimited limiter.
func New(cfg Config) *Limiter {
	l := &Limiter{}

	if cfg.RequestsPerSecond > 0 {
		l.minInterval = time.Duration(float64(time.Second) / cfg.RequestsPerSecond)
	}

	if cfg.MaxConcurrent > 0 {
		l.sem = make(chan struct{}, cfg.MaxConcurrent)
	}

	return l
}

// Acquire blocks until both the rate and concurrency budgets permit another
// request, then returns a release function that MUST be called once the request
// completes (use defer). It respects context cancellation; on cancellation it
// returns the context error and a no-op release.
func (l *Limiter) Acquire(ctx context.Context) (release func(), err error) {
	if l == nil {
		return func() {}, nil
	}

	// Concurrency gate first, so a slow request doesn't consume rate budget
	// while it waits for a concurrency slot.
	if l.sem != nil {
		select {
		case l.sem <- struct{}{}:
		case <-ctx.Done():
			return func() {}, ctx.Err()
		}
	}

	release = func() {
		if l.sem != nil {
			<-l.sem
		}
	}

	// Rate gate.
	if l.minInterval > 0 {
		l.mu.Lock()
		now := time.Now()
		wait := time.Duration(0)
		if l.next.After(now) {
			wait = l.next.Sub(now)
		}
		// Reserve the next slot.
		start := now
		if wait > 0 {
			start = l.next
		}
		l.next = start.Add(l.minInterval)
		l.mu.Unlock()

		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				release()
				return func() {}, ctx.Err()
			}
		}
	}

	return release, nil
}
