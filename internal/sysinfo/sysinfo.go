// Package sysinfo reads real system information from the Linux OS.
// It gathers CPU usage, memory stats, uptime, hostname, network interfaces,
// and network I/O counters from /proc and /sys.
package sysinfo

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SystemInfo holds real-time system metrics.
type SystemInfo struct {
	Hostname     string         `json:"hostname"`
	OS           string         `json:"os"`
	Kernel       string         `json:"kernel"`
	Uptime       string         `json:"uptime"`
	UptimeSec    float64        `json:"uptime_seconds"`
	CPUUsage     float64        `json:"cpu_usage_percent"`
	CPUCores     int            `json:"cpu_cores"`
	MemTotal     uint64         `json:"mem_total_bytes"`
	MemUsed      uint64         `json:"mem_used_bytes"`
	MemFree      uint64         `json:"mem_free_bytes"`
	MemPercent   float64        `json:"mem_usage_percent"`
	SwapTotal    uint64         `json:"swap_total_bytes"`
	SwapUsed     uint64         `json:"swap_used_bytes"`
	LoadAvg      string         `json:"load_average"`
	Interfaces   []NetInterface `json:"interfaces"`
	NetRxBytes   uint64         `json:"net_rx_bytes"`
	NetTxBytes   uint64         `json:"net_tx_bytes"`
	NetRxPackets uint64         `json:"net_rx_packets"`
	NetTxPackets uint64         `json:"net_tx_packets"`
}

// NetInterface describes a network interface and its addresses.
type NetInterface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	RxBytes   uint64   `json:"rx_bytes"`
	TxBytes   uint64   `json:"tx_bytes"`
}

// Gather collects real system information from the OS.
func Gather() SystemInfo {
	info := SystemInfo{
		OS:       runtime.GOOS,
		CPUCores: runtime.NumCPU(),
	}

	info.Hostname, _ = os.Hostname()
	info.Kernel = readKernel()
	info.UptimeSec = readUptime()
	info.Uptime = formatUptime(info.UptimeSec)
	info.LoadAvg = readLoadAvg()
	info.CPUUsage = readCPUUsage()

	info.MemTotal, info.MemUsed, info.MemFree, info.MemPercent = readMemory()
	info.SwapTotal, info.SwapUsed = readSwap()
	info.Interfaces, info.NetRxBytes, info.NetTxBytes, info.NetRxPackets, info.NetTxPackets = readNetworkInterfaces()

	return info
}

// ---------- Kernel ----------

func readKernel() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return runtime.GOOS + "/" + runtime.GOARCH
	}
	parts := strings.Fields(string(data))
	if len(parts) >= 3 {
		return parts[2] // e.g. "5.15.0-91-generic"
	}
	return strings.TrimSpace(string(data))
}

// ---------- Uptime ----------

func readUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(data))
	if len(parts) < 1 {
		return 0
	}
	v, _ := strconv.ParseFloat(parts[0], 64)
	return v
}

func formatUptime(seconds float64) string {
	if seconds <= 0 {
		return "unknown"
	}
	d := time.Duration(seconds) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

// ---------- Load Average ----------

func readLoadAvg() string {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "N/A"
	}
	parts := strings.Fields(string(data))
	if len(parts) >= 3 {
		return parts[0] + " " + parts[1] + " " + parts[2]
	}
	return strings.TrimSpace(string(data))
}

// ---------- CPU Usage ----------

// readCPUUsage samples /proc/stat twice 200ms apart to compute real usage.
func readCPUUsage() float64 {
	idle1, total1 := readCPUSample()
	if total1 == 0 {
		return 0
	}
	time.Sleep(200 * time.Millisecond)
	idle2, total2 := readCPUSample()
	if total2 == total1 {
		return 0
	}

	idleDelta := float64(idle2 - idle1)
	totalDelta := float64(total2 - total1)
	usage := (1.0 - idleDelta/totalDelta) * 100.0

	// Round to 1 decimal
	return float64(int(usage*10)) / 10
}

func readCPUSample() (idle, total uint64) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0, 0
			}
			for i := 1; i < len(fields); i++ {
				v, _ := strconv.ParseUint(fields[i], 10, 64)
				total += v
				if i == 4 { // idle is the 4th value (index 4)
					idle = v
				}
			}
			return
		}
	}
	return 0, 0
}

// ---------- Memory ----------

func readMemory() (total, used, free uint64, percent float64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0
	}
	defer file.Close()

	var memTotal, memFree, memAvailable, buffers, cached uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(parts[1], 10, 64)
		val *= 1024 // kB to bytes
		switch parts[0] {
		case "MemTotal:":
			memTotal = val
		case "MemFree:":
			memFree = val
		case "MemAvailable:":
			memAvailable = val
		case "Buffers:":
			buffers = val
		case "Cached:":
			cached = val
		}
	}

	// Used = Total - Available (or Total - Free - Buffers - Cached as fallback)
	if memAvailable > 0 {
		used = memTotal - memAvailable
	} else {
		used = memTotal - memFree - buffers - cached
	}
	free = memTotal - used

	if memTotal > 0 {
		percent = float64(used) / float64(memTotal) * 100.0
		percent = float64(int(percent*10)) / 10
	}

	return memTotal, used, free, percent
}

// ---------- Swap ----------

func readSwap() (total, used uint64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer file.Close()

	var swapTotal, swapFree uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(parts[1], 10, 64)
		val *= 1024
		switch parts[0] {
		case "SwapTotal:":
			swapTotal = val
		case "SwapFree:":
			swapFree = val
		}
	}
	return swapTotal, swapTotal - swapFree
}

// ---------- Network Interfaces ----------

func readNetworkInterfaces() (ifaces []NetInterface, totalRx, totalTx, totalRxPkt, totalTxPkt uint64) {
	ifaces = make([]NetInterface, 0)

	// Read /proc/net/dev for traffic counters
	devStats := readNetDev()

	// Use Go's net package for interface enumeration
	netIfaces, err := net.Interfaces()
	if err != nil {
		return ifaces, 0, 0, 0, 0
	}

	for _, iface := range netIfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue // skip loopback
		}

		ni := NetInterface{
			Name:      iface.Name,
			Addresses: make([]string, 0),
		}

		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ni.Addresses = append(ni.Addresses, a.String())
		}

		// Attach traffic stats from /proc/net/dev
		if stats, ok := devStats[iface.Name]; ok {
			ni.RxBytes = stats.rxBytes
			ni.TxBytes = stats.txBytes
			totalRx += stats.rxBytes
			totalTx += stats.txBytes
			totalRxPkt += stats.rxPackets
			totalTxPkt += stats.txPackets
		}

		ifaces = append(ifaces, ni)
	}

	return
}

type netDevStats struct {
	rxBytes   uint64
	rxPackets uint64
	txBytes   uint64
	txPackets uint64
}

// readNetDev parses /proc/net/dev for per-interface byte and packet counters.
func readNetDev() map[string]netDevStats {
	result := make(map[string]netDevStats)
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return result
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue // skip header lines
		}
		line := scanner.Text()
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colonIdx])
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 10 {
			continue
		}

		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		rxPackets, _ := strconv.ParseUint(fields[1], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		txPackets, _ := strconv.ParseUint(fields[9], 10, 64)

		result[name] = netDevStats{
			rxBytes:   rxBytes,
			rxPackets: rxPackets,
			txBytes:   txBytes,
			txPackets: txPackets,
		}
	}
	return result
}
