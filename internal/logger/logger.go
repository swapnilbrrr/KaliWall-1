// Package logger provides structured traffic logging for KaliWall.
// Logs are written to a local file with timestamps and can be queried for daily counts.
package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"kaliwall/internal/models"
)

// TrafficLogger writes structured log entries to a file.
type TrafficLogger struct {
	mu      sync.Mutex
	file    *os.File
	entries []models.TrafficEntry // in-memory buffer for API queries
}

// New opens (or creates) the log file and returns a TrafficLogger.
func New(path string) (*TrafficLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	tl := &TrafficLogger{
		file:    f,
		entries: make([]models.TrafficEntry, 0, 1024),
	}
	tl.Log("SYSTEM", "-", "-", "-", "KaliWall daemon started")
	return tl, nil
}

// Close flushes and closes the log file.
func (tl *TrafficLogger) Close() {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.file.Close()
}

// Log writes a single traffic event to the log file and in-memory buffer.
func (tl *TrafficLogger) Log(action, srcIP, dstIP, protocol, detail string) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	entry := models.TrafficEntry{
		Timestamp: time.Now(),
		Action:    action,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Protocol:  protocol,
		Detail:    detail,
	}

	// Write to file as JSON line
	line, _ := json.Marshal(entry)
	fmt.Fprintf(tl.file, "%s\n", line)

	// Keep in-memory (cap at 10000 entries)
	if len(tl.entries) >= 10000 {
		tl.entries = tl.entries[1:]
	}
	tl.entries = append(tl.entries, entry)
}

// RecentEntries returns the last n log entries.
func (tl *TrafficLogger) RecentEntries(n int) []models.TrafficEntry {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	if n <= 0 || n > len(tl.entries) {
		n = len(tl.entries)
	}
	start := len(tl.entries) - n
	out := make([]models.TrafficEntry, n)
	copy(out, tl.entries[start:])
	return out
}

// TodayCounts returns the number of BLOCK and ALLOW events logged today.
func (tl *TrafficLogger) TodayCounts() (blocked int, allowed int) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	today := time.Now().Truncate(24 * time.Hour)
	for _, e := range tl.entries {
		if e.Timestamp.Before(today) {
			continue
		}
		upper := strings.ToUpper(e.Action)
		switch {
		case upper == "BLOCK" || upper == "DROP":
			blocked++
		case upper == "ALLOW" || upper == "ACCEPT":
			allowed++
		}
	}
	return
}

