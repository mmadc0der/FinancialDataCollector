package kernel

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/data-kernel/internal/metrics"
)

// activityTracker keeps track of identifiers seen within a sliding TTL window.
type activityTracker struct {
	mu       sync.Mutex
	entries  map[string]time.Time
	ttl      time.Duration
	ticker   *time.Ticker
	onUpdate func(int)
}

func newActivityTracker(ttl time.Duration, onUpdate func(int)) *activityTracker {
	if ttl <= 0 {
		tl = 5 * time.Minute
	}
	at := &activityTracker{
		entries:  make(map[string]time.Time),
		ttl:      ttl,
		onUpdate: onUpdate,
	}
	at.ticker = time.NewTicker(ttl / 2)
	go at.cleanupLoop()
	return at
}

func (a *activityTracker) cleanupLoop() {
	for range a.ticker.C {
		a.cleanup()
	}
}

func (a *activityTracker) cleanup() {
	now := time.Now()
	a.mu.Lock()
	for id, ts := range a.entries {
		if now.Sub(ts) > a.ttl {
			delete(a.entries, id)
		}
	}
	count := len(a.entries)
	a.mu.Unlock()
	if a.onUpdate != nil {
		a.onUpdate(count)
	}
}

// mark records the identifier and returns the current number of active entries.
func (a *activityTracker) mark(id string) int {
	if id == "" {
		return 0
	}
	now := time.Now()
	a.mu.Lock()
	a.entries[id] = now
	for existing, ts := range a.entries {
		if now.Sub(ts) > a.ttl {
			delete(a.entries, existing)
		}
	}
	count := len(a.entries)
	a.mu.Unlock()
	if a.onUpdate != nil {
		a.onUpdate(count)
	}
	return count
}

func redisIDToTime(id string) (time.Time, bool) {
	parts := strings.Split(id, "-")
	if len(parts) == 0 || parts[0] == "" {
		return time.Time{}, false
	}
	ms, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.UnixMilli(ms), true
}

func observeRedisLag(id string) {
	if ts, ok := redisIDToTime(id); ok {
		lag := time.Since(ts).Seconds()
		if lag >= 0 {
			metrics.RedisMessageLag.Observe(lag)
		}
	}
}

func (k *Kernel) ackStreamWithLatency(ctx context.Context, stream string, started time.Time, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	err := k.rd.AckStream(ctx, stream, ids...)
	if err == nil {
		metrics.RedisAckLatency.Observe(time.Since(started).Seconds())
	}
	return err
}

