package flow

import (
	"fmt"
	"sync"
	"time"

	"kaliwall/internal/dpi/types"
)

// State stores flow counters and timestamps.
type State struct {
	FirstSeen   time.Time
	LastSeen    time.Time
	PacketCount int64
	ByteCount   int64
}

type srcRateState struct {
	WindowStart time.Time
	Count       int
}

// Tracker is a concurrent-safe 5-tuple flow table.
type Tracker struct {
	mu              sync.RWMutex
	flows           map[types.FiveTuple]*State
	srcRates        map[string]*srcRateState
	flowTimeout     time.Duration
	cleanupInterval time.Duration
	rateLimitPerSec int
	stopCh          chan struct{}
}

func New(flowTimeout, cleanupInterval time.Duration, rateLimitPerSec int) *Tracker {
	if flowTimeout <= 0 {
		flowTimeout = 2 * time.Minute
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 30 * time.Second
	}
	return &Tracker{
		flows:           make(map[types.FiveTuple]*State, 4096),
		srcRates:        make(map[string]*srcRateState, 4096),
		flowTimeout:     flowTimeout,
		cleanupInterval: cleanupInterval,
		rateLimitPerSec: rateLimitPerSec,
		stopCh:          make(chan struct{}),
	}
}

func (t *Tracker) Start() {
	go t.cleanupLoop()
}

func (t *Tracker) Stop() {
	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
}

// Touch updates flow stats and returns current state copy.
func (t *Tracker) Touch(tuple types.FiveTuple, payloadBytes int) State {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.flows[tuple]
	if !ok {
		st = &State{FirstSeen: now, LastSeen: now}
		t.flows[tuple] = st
	}
	st.LastSeen = now
	st.PacketCount++
	st.ByteCount += int64(payloadBytes)
	return *st
}

// IsRateLimited applies a simple per-source per-second limiter.
func (t *Tracker) IsRateLimited(srcIP string) bool {
	if t.rateLimitPerSec <= 0 || srcIP == "" {
		return false
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	rs, ok := t.srcRates[srcIP]
	if !ok {
		t.srcRates[srcIP] = &srcRateState{WindowStart: now, Count: 1}
		return false
	}
	if now.Sub(rs.WindowStart) >= time.Second {
		rs.WindowStart = now
		rs.Count = 1
		return false
	}
	rs.Count++
	return rs.Count > t.rateLimitPerSec
}

func (t *Tracker) SnapshotSize() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.flows)
}

func (t *Tracker) cleanupLoop() {
	ticker := time.NewTicker(t.cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.cleanupExpired()
		}
	}
}

func (t *Tracker) cleanupExpired() {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.flows {
		if now.Sub(v.LastSeen) > t.flowTimeout {
			delete(t.flows, k)
		}
	}
	for ip, rs := range t.srcRates {
		if now.Sub(rs.WindowStart) > 3*time.Second {
			delete(t.srcRates, ip)
		}
	}
}

func (t *Tracker) String() string {
	return fmt.Sprintf("flows=%d timeout=%s", t.SnapshotSize(), t.flowTimeout)
}
