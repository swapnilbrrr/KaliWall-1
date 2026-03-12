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

// GenerateDemoLogs creates sample log entries for the demo UI.
func (tl *TrafficLogger) GenerateDemoLogs() {
	demoEntries := []struct {
		action, src, dst, proto, detail string
	}{
		{"ALLOW", "192.168.1.50", "192.168.1.10", "tcp", "SSH connection established on port 22"},
		{"ALLOW", "10.0.0.5", "192.168.1.10", "tcp", "HTTPS request to port 443"},
		{"BLOCK", "45.33.32.156", "192.168.1.10", "tcp", "Blocked incoming Telnet on port 23"},
		{"ALLOW", "192.168.1.10", "8.8.8.8", "udp", "DNS query to port 53"},
		{"BLOCK", "103.21.244.0", "192.168.1.10", "tcp", "Blocked RDP attempt on port 3389"},
		{"ALLOW", "172.16.0.3", "192.168.1.10", "tcp", "HTTP request to port 80"},
		{"BLOCK", "185.220.101.1", "192.168.1.10", "tcp", "Dropped port scan on port 445"},
		{"ALLOW", "10.0.0.12", "192.168.1.10", "tcp", "MySQL connection on port 3306"},
		{"ALLOW", "192.168.1.10", "1.1.1.1", "udp", "DNS query to port 53"},
		{"BLOCK", "91.240.118.0", "192.168.1.10", "tcp", "Blocked brute-force SSH on port 22"},
		{"ALLOW", "192.168.1.100", "192.168.1.10", "icmp", "Ping request"},
		{"BLOCK", "198.51.100.0", "192.168.1.10", "tcp", "Dropped connection on port 8443"},
	}
	for _, d := range demoEntries {
		tl.Log(d.action, d.src, d.dst, d.proto, d.detail)
	}
}
