package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNilLimiterUnlimited(t *testing.T) {
	var l *Limiter
	release, err := l.Acquire(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	release()
}

func TestRateCap(t *testing.T) {
	l := New(Config{RequestsPerSecond: 50}) // 20ms min interval
	start := time.Now()
	for i := 0; i < 5; i++ {
		release, err := l.Acquire(context.Background())
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		release()
	}
	// 5 acquisitions at 20ms spacing => at least ~80ms (4 gaps).
	elapsed := time.Since(start)
	if elapsed < 60*time.Millisecond {
		t.Errorf("rate cap not enforced: 5 acquisitions took %v, want >= 60ms", elapsed)
	}
}

func TestConcurrencyCap(t *testing.T) {
	l := New(Config{MaxConcurrent: 2})
	var inflight, maxSeen int32

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := l.Acquire(context.Background())
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			defer release()

			cur := atomic.AddInt32(&inflight, 1)
			for {
				m := atomic.LoadInt32(&maxSeen)
				if cur <= m || atomic.CompareAndSwapInt32(&maxSeen, m, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt32(&inflight, -1)
		}()
	}
	wg.Wait()

	if maxSeen > 2 {
		t.Errorf("concurrency cap exceeded: saw %d in flight, want <= 2", maxSeen)
	}
}

func TestContextCancel(t *testing.T) {
	l := New(Config{MaxConcurrent: 1})
	// Hold the only slot.
	release, err := l.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Acquire(ctx); err == nil {
		t.Error("expected context error when slot unavailable and ctx cancelled")
	}
}
