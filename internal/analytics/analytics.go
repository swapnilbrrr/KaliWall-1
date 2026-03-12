// Package analytics provides real-time traffic analytics and bandwidth tracking.
// It samples /proc/net/dev for per-interface byte counters regularly and
// computes protocol breakdown, top talkers, and blocked vs allowed ratios
// from the traffic logger.
package analytics

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"kaliwall/internal/logger"
	"kaliwall/internal/models"
)

const (
	maxHistoryPoints = 120 // 120 samples = 10 minutes at 5s interval
	sampleInterval   = 5 * time.Second
)

// BandwidthSample stores a single point-in-time bandwidth measurement.
type BandwidthSample struct {
	Time    time.Time `json:"time"`
	RxBps   uint64    `json:"rx_bps"`   // bytes per second received
	TxBps   uint64    `json:"tx_bps"`   // bytes per second sent
}

// TopTalker represents an IP with aggregated byte/connection count.
type TopTalker struct {
	IP     string `json:"ip"`
	Count  int    `json:"count"`  // number of log entries
	Label  string `json:"label"`  // "src" or "dst"
}

// ProtocolCount represents protocol occurrence count.
type ProtocolCount struct {
	Protocol string `json:"protocol"`
	Count    int    `json:"count"`
}

// Snapshot holds a point-in-time analytics snapshot.
type Snapshot struct {
	Bandwidth     []BandwidthSample `json:"bandwidth"`
	TopTalkers    []TopTalker       `json:"top_talkers"`
	Protocols     []ProtocolCount   `json:"protocols"`
	BlockedCount  int               `json:"blocked_count"`
	AllowedCount  int               `json:"allowed_count"`
	TotalEvents   int               `json:"total_events"`
}

// Service runs background bandwidth sampling and provides computed analytics.
type Service struct {
	mu          sync.RWMutex
	logger      *logger.TrafficLogger
	history     []BandwidthSample
	prevRx      uint64
	prevTx      uint64
	prevTime    time.Time
	stop        chan struct{}
	wg          sync.WaitGroup
	subscribers map[uint64]chan BandwidthSample
	nextSubID   uint64
}

// New creates a new analytics service.
func New(l *logger.TrafficLogger) *Service {
	rx, tx := readTotalBytes()
	return &Service{
		logger:      l,
		history:     make([]BandwidthSample, 0, maxHistoryPoints),
		prevRx:      rx,
		prevTx:      tx,
		prevTime:    time.Now(),
		stop:        make(chan struct{}),
		subscribers: make(map[uint64]chan BandwidthSample),
	}
}

// Start begins background bandwidth sampling.
func (s *Service) Start() {
	s.wg.Add(1)
	go s.sampleLoop()
	fmt.Println("[+] Analytics engine started — sampling bandwidth every 5s")
}

// Stop shuts down the sampler.
func (s *Service) Stop() {
	close(s.stop)
	s.wg.Wait()
}

func (s *Service) sampleLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.takeSample()
		}
	}
}

func (s *Service) takeSample() {
	rx, tx := readTotalBytes()
	now := time.Now()

	s.mu.Lock()
	elapsed := now.Sub(s.prevTime).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	sample := BandwidthSample{
		Time:  now,
		RxBps: uint64(float64(rx-s.prevRx) / elapsed),
		TxBps: uint64(float64(tx-s.prevTx) / elapsed),
	}

	s.prevRx = rx
	s.prevTx = tx
	s.prevTime = now

	s.history = append(s.history, sample)
	if len(s.history) > maxHistoryPoints {
		s.history = s.history[len(s.history)-maxHistoryPoints:]
	}

	// Notify subscribers
	for _, ch := range s.subscribers {
		select {
		case ch <- sample:
		default:
		}
	}
	s.mu.Unlock()
}

// Subscribe returns a channel that receives live bandwidth samples.
func (s *Service) Subscribe() (uint64, chan BandwidthSample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextSubID++
	id := s.nextSubID
	ch := make(chan BandwidthSample, 32)
	s.subscribers[id] = ch
	return id, ch
}

// Unsubscribe removes a subscriber.
func (s *Service) Unsubscribe(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.subscribers[id]; ok {
		close(ch)
		delete(s.subscribers, id)
	}
}

// GetSnapshot computes the full analytics snapshot from current data.
func (s *Service) GetSnapshot() Snapshot {
	s.mu.RLock()
	hist := make([]BandwidthSample, len(s.history))
	copy(hist, s.history)
	s.mu.RUnlock()

	entries := s.logger.RecentEntries(1000)
	topTalkers := computeTopTalkers(entries, 10)
	protocols := computeProtocols(entries)
	blocked, allowed := countActions(entries)

	return Snapshot{
		Bandwidth:    hist,
		TopTalkers:   topTalkers,
		Protocols:    protocols,
		BlockedCount: blocked,
		AllowedCount: allowed,
		TotalEvents:  len(entries),
	}
}

// ---------- Aggregation helpers ----------

func computeTopTalkers(entries []models.TrafficEntry, limit int) []TopTalker {
	counts := make(map[string]int)
	for _, e := range entries {
		if e.SrcIP != "" && e.SrcIP != "-" {
			counts[e.SrcIP]++
		}
		if e.DstIP != "" && e.DstIP != "-" {
			counts[e.DstIP]++
		}
	}

	talkers := make([]TopTalker, 0, len(counts))
	for ip, count := range counts {
		talkers = append(talkers, TopTalker{IP: ip, Count: count})
	}
	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].Count > talkers[j].Count
	})
	if len(talkers) > limit {
		talkers = talkers[:limit]
	}
	return talkers
}

func computeProtocols(entries []models.TrafficEntry) []ProtocolCount {
	counts := make(map[string]int)
	for _, e := range entries {
		proto := strings.ToUpper(e.Protocol)
		if proto == "" || proto == "-" {
			proto = "OTHER"
		}
		counts[proto]++
	}

	result := make([]ProtocolCount, 0, len(counts))
	for proto, count := range counts {
		result = append(result, ProtocolCount{Protocol: proto, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	return result
}

func countActions(entries []models.TrafficEntry) (blocked int, allowed int) {
	for _, e := range entries {
		upper := strings.ToUpper(e.Action)
		switch {
		case upper == "BLOCK" || upper == "DROP" || upper == "REJECT":
			blocked++
		case upper == "ALLOW" || upper == "ACCEPT":
			allowed++
		}
	}
	return
}

// readTotalBytes reads aggregate RX and TX bytes from /proc/net/dev.
func readTotalBytes() (rx, tx uint64) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue // skip headers
		}
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		ifname := strings.TrimSpace(parts[0])
		if ifname == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 10 {
			continue
		}
		var r, t uint64
		fmt.Sscanf(fields[0], "%d", &r)
		fmt.Sscanf(fields[8], "%d", &t)
		rx += r
		tx += t
	}
	return
}
