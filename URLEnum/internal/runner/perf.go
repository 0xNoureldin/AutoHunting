package runner

import (
	"context"
	"sync"
	"time"
)

type limiter struct {
	mu       sync.Mutex
	last     time.Time
	interval time.Duration
}

func newLimiter(interval time.Duration) *limiter {
	return &limiter{interval: interval}
}

func (l *limiter) Wait(ctx context.Context) error {
	if l == nil || l.interval <= 0 {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	wait := l.last.Add(l.interval).Sub(now)
	if wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !t.Stop() {
				<-t.C
			}
			return ctx.Err()
		case <-t.C:
		}
	}

	l.last = time.Now()
	return nil
}

func limiterForSource(name string) *limiter {
	switch name {
	case "webarchive":
		return newLimiter(800 * time.Millisecond)
	case "commoncrawl":
		return newLimiter(1200 * time.Millisecond)
	case "urlscan":
		return newLimiter(1500 * time.Millisecond)
	default:
		return newLimiter(1000 * time.Millisecond)
	}
}
