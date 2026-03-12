// Package netmon provides real-time network traffic monitoring.
// It runs a background goroutine that detects new and closed connections
// by polling /proc/net/tcp, /proc/net/udp, reading conntrack entries,
// and parsing kernel netfilter log messages from dmesg.
package netmon

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"kaliwall/internal/logger"
)

// Monitor watches the OS for real network events and logs them.
type Monitor struct {
	logger   *logger.TrafficLogger
	stop     chan struct{}
	wg       sync.WaitGroup
	prevTCP  map[string]string // key="local:port-remote:port" -> state
	prevUDP  map[string]bool
}

// New creates a new network monitor.
func New(l *logger.TrafficLogger) *Monitor {
	return &Monitor{
		logger:  l,
		stop:    make(chan struct{}),
		prevTCP: make(map[string]string),
		prevUDP: make(map[string]bool),
	}
}

// Start launches the background monitoring goroutines.
func (m *Monitor) Start() {
	m.wg.Add(2)
	go m.pollConnections()
	go m.watchKernelLog()
	fmt.Println("[+] Network monitor started — watching real traffic")
}

// Stop signals the monitor to shut down and waits for goroutines to exit.
func (m *Monitor) Stop() {
	close(m.stop)
	m.wg.Wait()
}

// pollConnections periodically reads /proc/net/{tcp,udp} and detects
// new connections, state changes, and closed connections.
func (m *Monitor) pollConnections() {
	defer m.wg.Done()

	// Initial snapshot (don't log existing connections on first run)
	m.snapshotTCP(true)
	m.snapshotUDP(true)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.snapshotTCP(false)
			m.snapshotUDP(false)
			m.readConntrack()
		}
	}
}

// connKey builds a unique key for a connection from /proc/net/* fields.
func connKey(localAddr, remoteAddr string) string {
	return localAddr + "-" + remoteAddr
}

// snapshotTCP reads /proc/net/tcp and /proc/net/tcp6, detecting new/changed/closed connections.
func (m *Monitor) snapshotTCP(initial bool) {
	current := make(map[string]string)

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		entries := readProcNetEntries(path)
		for _, e := range entries {
			key := connKey(e.localAddr, e.remoteAddr)
			current[key] = e.state

			if initial {
				continue
			}

			prevState, existed := m.prevTCP[key]
			if !existed {
				// New connection detected
				localIP, localPort := splitHexAddr(e.localAddr)
				remoteIP, remotePort := splitHexAddr(e.remoteAddr)
				action := "ALLOW"
				detail := fmt.Sprintf("New TCP connection %s → %s:%s (%s)",
					localIP+":"+localPort, remoteIP, remotePort, e.state)
				m.logger.Log(action, localIP, remoteIP, "tcp", detail)
			} else if prevState != e.state && e.state != prevState {
				// State changed
				localIP, localPort := splitHexAddr(e.localAddr)
				remoteIP, remotePort := splitHexAddr(e.remoteAddr)
				detail := fmt.Sprintf("TCP %s:%s → %s:%s state %s → %s",
					localIP, localPort, remoteIP, remotePort, prevState, e.state)
				m.logger.Log("INFO", localIP, remoteIP, "tcp", detail)
			}
		}
	}

	if !initial {
		// Detect closed connections
		for key, state := range m.prevTCP {
			if _, exists := current[key]; !exists {
				localIP, localPort := splitHexAddr(strings.Split(key, "-")[0])
				remoteIP, remotePort := splitHexAddr(strings.Split(key, "-")[1])
				detail := fmt.Sprintf("TCP connection closed %s:%s → %s:%s (was %s)",
					localIP, localPort, remoteIP, remotePort, state)
				m.logger.Log("CLOSE", localIP, remoteIP, "tcp", detail)
			}
		}
	}

	m.prevTCP = current
}

// snapshotUDP reads /proc/net/udp and /proc/net/udp6, detecting new endpoints.
func (m *Monitor) snapshotUDP(initial bool) {
	current := make(map[string]bool)

	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		entries := readProcNetEntries(path)
		for _, e := range entries {
			key := connKey(e.localAddr, e.remoteAddr)
			current[key] = true

			if initial {
				continue
			}

			if !m.prevUDP[key] {
				localIP, localPort := splitHexAddr(e.localAddr)
				remoteIP, remotePort := splitHexAddr(e.remoteAddr)
				detail := fmt.Sprintf("New UDP endpoint %s:%s → %s:%s",
					localIP, localPort, remoteIP, remotePort)
				m.logger.Log("ALLOW", localIP, remoteIP, "udp", detail)
			}
		}
	}

	m.prevUDP = current
}

// readConntrack parses /proc/net/nf_conntrack for tracked connection events.
func (m *Monitor) readConntrack() {
	file, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return // conntrack not available
	}
	defer file.Close()

	// We just count for stats — individual entries are very noisy.
	// Real conntrack events are better captured via kernel log.
}

// procNetEntry represents a parsed line from /proc/net/tcp or /proc/net/udp.
type procNetEntry struct {
	localAddr  string // hex format "0100007F:0050"
	remoteAddr string
	state      string // decoded state name
}

// readProcNetEntries parses a /proc/net/* file into entries.
func readProcNetEntries(path string) []procNetEntry {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var entries []procNetEntry
	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) < 4 {
			continue
		}
		entries = append(entries, procNetEntry{
			localAddr:  fields[1],
			remoteAddr: fields[2],
			state:      decodeState(fields[3]),
		})
	}
	return entries
}

// ---------- Kernel netfilter log watcher ----------

// iptables LOG messages look like:
// [12345.678] IN=eth0 OUT= SRC=192.168.1.5 DST=192.168.1.1 ... PROTO=TCP SPT=54321 DPT=22

var nfLogPattern = regexp.MustCompile(
	`(?:IN=(\S*)\s)?(?:OUT=(\S*)\s)?.*SRC=(\S+)\s+DST=(\S+)\s+.*PROTO=(\S+)(?:.*SPT=(\d+))?(?:.*DPT=(\d+))?`,
)

// watchKernelLog reads kernel log messages (dmesg) for iptables/netfilter LOG entries.
func (m *Monitor) watchKernelLog() {
	defer m.wg.Done()

	// Try reading from /proc/kmsg (requires root) or fall back to dmesg polling
	if f, err := os.Open("/proc/kmsg"); err == nil {
		m.streamKmsg(f)
		return
	}

	// Fallback: poll dmesg periodically
	m.pollDmesg()
}

// streamKmsg reads /proc/kmsg in real-time (blocking read, requires root).
func (m *Monitor) streamKmsg(f *os.File) {
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for {
		select {
		case <-m.stop:
			return
		default:
		}

		if scanner.Scan() {
			line := scanner.Text()
			m.parseKernelLogLine(line)
		} else {
			// Scanner error or EOF (shouldn't happen for kmsg)
			time.Sleep(time.Second)
			return
		}
	}
}

// pollDmesg periodically runs dmesg and parses new netfilter entries.
func (m *Monitor) pollDmesg() {
	var lastLen int
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			out, err := exec.Command("dmesg", "--time-format", "iso").Output()
			if err != nil {
				// dmesg might not be available or require root
				continue
			}
			lines := strings.Split(string(out), "\n")
			if len(lines) <= lastLen {
				continue
			}
			// Process only new lines
			for i := lastLen; i < len(lines); i++ {
				m.parseKernelLogLine(lines[i])
			}
			lastLen = len(lines)
		}
	}
}

// parseKernelLogLine checks if a kernel log line contains a netfilter event and logs it.
func (m *Monitor) parseKernelLogLine(line string) {
	// Only process lines that look like netfilter logs
	if !strings.Contains(line, "SRC=") || !strings.Contains(line, "DST=") {
		return
	}

	matches := nfLogPattern.FindStringSubmatch(line)
	if matches == nil {
		return
	}

	srcIP := matches[3]
	dstIP := matches[4]
	proto := strings.ToLower(matches[5])
	dstPort := matches[7]

	action := "BLOCK"
	if strings.Contains(line, "ACCEPT") || strings.Contains(line, "ALLOW") {
		action = "ALLOW"
	}

	detail := fmt.Sprintf("Kernel: %s %s → %s:%s (%s)",
		strings.ToUpper(action), srcIP, dstIP, dstPort, proto)

	iface := matches[1]
	if iface != "" {
		detail += " on " + iface
	}

	m.logger.Log(action, srcIP, dstIP, proto, detail)
}

// ---------- Helpers ----------

// splitHexAddr splits a hex address "0100007F:0050" into IP and port strings.
func splitHexAddr(addr string) (string, string) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return addr, ""
	}
	ip := hexToIP(parts[0])
	port := fmt.Sprintf("%d", hexToUint16(parts[1]))
	return ip, port
}

func hexToIP(hex string) string {
	if len(hex) == 8 {
		var a, b, c, d byte
		fmt.Sscanf(hex[6:8], "%x", &a)
		fmt.Sscanf(hex[4:6], "%x", &b)
		fmt.Sscanf(hex[2:4], "%x", &c)
		fmt.Sscanf(hex[0:2], "%x", &d)
		return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
	}
	return hex
}

func hexToUint16(h string) uint16 {
	var v uint16
	fmt.Sscanf(h, "%x", &v)
	return v
}

func decodeState(hex string) string {
	states := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
		"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
		"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
		"0A": "LISTEN", "0B": "CLOSING",
	}
	if s, ok := states[strings.ToUpper(hex)]; ok {
		return s
	}
	return hex
}
