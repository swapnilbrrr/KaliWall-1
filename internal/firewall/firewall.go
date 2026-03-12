// Package firewall manages iptables/nftables rule application and in-memory rule storage.
// On Linux with root privileges it executes real iptables commands.
// Otherwise it operates in demo mode with in-memory rules only.
package firewall

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"kaliwall/internal/logger"
	"kaliwall/internal/models"
)

// Engine is the core firewall management component.
type Engine struct {
	mu       sync.RWMutex
	rules    []models.Rule
	logger   *logger.TrafficLogger
	liveMode bool // true when running as root on Linux with iptables available
}

// New creates a new firewall engine and detects whether live iptables mode is available.
func New(l *logger.TrafficLogger) *Engine {
	e := &Engine{
		rules:  make([]models.Rule, 0),
		logger: l,
	}
	e.detectMode()
	return e
}

// detectMode checks if iptables is available and we have root privileges.
func (e *Engine) detectMode() {
	if os.Getuid() != 0 {
		fmt.Println("[!] Not running as root — demo mode (rules stored in-memory only)")
		e.liveMode = false
		return
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		fmt.Println("[!] iptables not found — demo mode")
		e.liveMode = false
		return
	}
	fmt.Println("[+] Running as root with iptables — live mode enabled")
	e.liveMode = true
}

// ---------- Rule CRUD ----------

// AddRule validates, stores, and optionally applies a firewall rule.
func (e *Engine) AddRule(req models.RuleRequest) (models.Rule, error) {
	if err := validateRuleRequest(req); err != nil {
		return models.Rule{}, err
	}

	rule := models.Rule{
		ID:        uuid.New().String(),
		Chain:     strings.ToUpper(req.Chain),
		Protocol:  strings.ToLower(req.Protocol),
		SrcIP:     normalise(req.SrcIP),
		DstIP:     normalise(req.DstIP),
		SrcPort:   normalise(req.SrcPort),
		DstPort:   normalise(req.DstPort),
		Action:    strings.ToUpper(req.Action),
		Comment:   req.Comment,
		Enabled:   req.Enabled,
		CreatedAt: time.Now(),
	}

	e.mu.Lock()
	e.rules = append(e.rules, rule)
	e.mu.Unlock()

	// Apply to iptables if live
	if e.liveMode && rule.Enabled {
		if err := e.applyRule(rule); err != nil {
			e.logger.Log("ERROR", "-", "-", "-", fmt.Sprintf("iptables apply failed: %v", err))
		}
	}

	e.logger.Log("CONFIG", "-", "-", "-",
		fmt.Sprintf("Rule added: %s %s %s src=%s dst=%s dport=%s [%s]",
			rule.Action, rule.Chain, rule.Protocol, rule.SrcIP, rule.DstIP, rule.DstPort, rule.Comment))

	return rule, nil
}

// RemoveRule deletes a rule by ID and removes it from iptables if live.
func (e *Engine) RemoveRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	idx := -1
	for i, r := range e.rules {
		if r.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("rule %s not found", id)
	}

	rule := e.rules[idx]

	// Remove from iptables if live
	if e.liveMode && rule.Enabled {
		e.removeIPTablesRule(rule)
	}

	e.rules = append(e.rules[:idx], e.rules[idx+1:]...)
	e.logger.Log("CONFIG", "-", "-", "-", fmt.Sprintf("Rule removed: %s", id))
	return nil
}

// ToggleRule enables or disables a rule by ID.
func (e *Engine) ToggleRule(id string) (models.Rule, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, r := range e.rules {
		if r.ID == id {
			e.rules[i].Enabled = !e.rules[i].Enabled
			if e.liveMode {
				if e.rules[i].Enabled {
					e.applyRule(e.rules[i])
				} else {
					e.removeIPTablesRule(e.rules[i])
				}
			}
			return e.rules[i], nil
		}
	}
	return models.Rule{}, fmt.Errorf("rule %s not found", id)
}

// ListRules returns a copy of all rules.
func (e *Engine) ListRules() []models.Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]models.Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// GetRule returns a single rule by ID.
func (e *Engine) GetRule(id string) (models.Rule, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, r := range e.rules {
		if r.ID == id {
			return r, nil
		}
	}
	return models.Rule{}, fmt.Errorf("rule %s not found", id)
}

// ---------- Statistics ----------

// Stats computes dashboard statistics.
func (e *Engine) Stats() models.DashboardStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	active := 0
	for _, r := range e.rules {
		if r.Enabled {
			active++
		}
	}

	blocked, allowed := e.logger.TodayCounts()
	conns := len(e.ActiveConnections())

	return models.DashboardStats{
		TotalRules:        len(e.rules),
		ActiveRules:       active,
		BlockedToday:      blocked,
		AllowedToday:      allowed,
		ActiveConnections: conns,
	}
}

// ActiveConnections reads /proc/net/tcp to list active TCP connections.
func (e *Engine) ActiveConnections() []models.Connection {
	conns := make([]models.Connection, 0)

	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		// Not on Linux or no access — return demo data
		return demoConnections()
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip header

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		localIP, localPort := parseHexAddr(fields[1])
		remoteIP, remotePort := parseHexAddr(fields[2])
		state := tcpState(fields[3])

		conns = append(conns, models.Connection{
			Protocol:   "tcp",
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      state,
		})
	}
	return conns
}

// ---------- iptables interaction ----------

// applyRule translates a Rule into an iptables -A command and executes it.
func (e *Engine) applyRule(r models.Rule) error {
	args := buildIPTablesArgs("-A", r)
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

// removeIPTablesRule translates a Rule into an iptables -D command and executes it.
func (e *Engine) removeIPTablesRule(r models.Rule) {
	args := buildIPTablesArgs("-D", r)
	cmd := exec.Command("iptables", args...)
	cmd.CombinedOutput() // best-effort removal
}

// buildIPTablesArgs creates the argument slice for an iptables command.
func buildIPTablesArgs(op string, r models.Rule) []string {
	args := []string{op, r.Chain}

	if r.Protocol != "" && r.Protocol != "all" {
		args = append(args, "-p", r.Protocol)
	}
	if r.SrcIP != "" && r.SrcIP != "any" {
		args = append(args, "-s", r.SrcIP)
	}
	if r.DstIP != "" && r.DstIP != "any" {
		args = append(args, "-d", r.DstIP)
	}
	if r.DstPort != "" && r.DstPort != "any" {
		args = append(args, "--dport", r.DstPort)
	}
	if r.SrcPort != "" && r.SrcPort != "any" {
		args = append(args, "--sport", r.SrcPort)
	}
	args = append(args, "-j", r.Action)

	if r.Comment != "" {
		args = append(args, "-m", "comment", "--comment", r.Comment)
	}

	return args
}

// ---------- Sample / Demo Rules ----------

// LoadSampleRules populates a set of demonstration firewall rules.
func (e *Engine) LoadSampleRules() {
	samples := []models.RuleRequest{
		{Chain: "INPUT", Protocol: "tcp", SrcIP: "any", DstIP: "any", SrcPort: "any", DstPort: "22", Action: "ACCEPT", Comment: "Allow SSH", Enabled: true},
		{Chain: "INPUT", Protocol: "tcp", SrcIP: "any", DstIP: "any", SrcPort: "any", DstPort: "80", Action: "ACCEPT", Comment: "Allow HTTP", Enabled: true},
		{Chain: "INPUT", Protocol: "tcp", SrcIP: "any", DstIP: "any", SrcPort: "any", DstPort: "443", Action: "ACCEPT", Comment: "Allow HTTPS", Enabled: true},
		{Chain: "INPUT", Protocol: "icmp", SrcIP: "any", DstIP: "any", SrcPort: "any", DstPort: "any", Action: "ACCEPT", Comment: "Allow Ping", Enabled: true},
		{Chain: "INPUT", Protocol: "tcp", SrcIP: "10.0.0.0/8", DstIP: "any", SrcPort: "any", DstPort: "3306", Action: "ACCEPT", Comment: "MySQL from internal", Enabled: true},
		{Chain: "INPUT", Protocol: "tcp", SrcIP: "any", DstIP: "any", SrcPort: "any", DstPort: "23", Action: "DROP", Comment: "Block Telnet", Enabled: true},
		{Chain: "INPUT", Protocol: "tcp", SrcIP: "any", DstIP: "any", SrcPort: "any", DstPort: "3389", Action: "DROP", Comment: "Block RDP", Enabled: false},
		{Chain: "FORWARD", Protocol: "all", SrcIP: "192.168.1.0/24", DstIP: "any", SrcPort: "any", DstPort: "any", Action: "ACCEPT", Comment: "Forward LAN traffic", Enabled: true},
		{Chain: "OUTPUT", Protocol: "tcp", SrcIP: "any", DstIP: "any", SrcPort: "any", DstPort: "53", Action: "ACCEPT", Comment: "Allow DNS out", Enabled: true},
		{Chain: "OUTPUT", Protocol: "udp", SrcIP: "any", DstIP: "any", SrcPort: "any", DstPort: "53", Action: "ACCEPT", Comment: "Allow DNS out (UDP)", Enabled: true},
	}

	for _, s := range samples {
		e.AddRule(s)
	}
	fmt.Printf("[+] Loaded %d sample firewall rules\n", len(samples))
}

// ---------- Validation ----------

var validChains = map[string]bool{"INPUT": true, "OUTPUT": true, "FORWARD": true}
var validActions = map[string]bool{"ACCEPT": true, "DROP": true, "REJECT": true}
var validProtocols = map[string]bool{"tcp": true, "udp": true, "icmp": true, "all": true}
var portRegex = regexp.MustCompile(`^(\d{1,5}|any)$`)

func validateRuleRequest(req models.RuleRequest) error {
	chain := strings.ToUpper(req.Chain)
	if !validChains[chain] {
		return fmt.Errorf("invalid chain: %s (must be INPUT, OUTPUT, or FORWARD)", req.Chain)
	}
	action := strings.ToUpper(req.Action)
	if !validActions[action] {
		return fmt.Errorf("invalid action: %s (must be ACCEPT, DROP, or REJECT)", req.Action)
	}
	proto := strings.ToLower(req.Protocol)
	if !validProtocols[proto] {
		return fmt.Errorf("invalid protocol: %s (must be tcp, udp, icmp, or all)", req.Protocol)
	}
	// Validate IP addresses (basic)
	if req.SrcIP != "any" && req.SrcIP != "" {
		if !isValidCIDROrIP(req.SrcIP) {
			return fmt.Errorf("invalid source IP: %s", req.SrcIP)
		}
	}
	if req.DstIP != "any" && req.DstIP != "" {
		if !isValidCIDROrIP(req.DstIP) {
			return fmt.Errorf("invalid destination IP: %s", req.DstIP)
		}
	}
	// Validate ports
	if req.SrcPort != "" && !portRegex.MatchString(req.SrcPort) {
		return fmt.Errorf("invalid source port: %s", req.SrcPort)
	}
	if req.DstPort != "" && !portRegex.MatchString(req.DstPort) {
		return fmt.Errorf("invalid destination port: %s", req.DstPort)
	}
	return nil
}

func isValidCIDROrIP(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// ---------- Helpers ----------

func normalise(v string) string {
	if v == "" {
		return "any"
	}
	return v
}

// parseHexAddr converts /proc/net/tcp hex address (e.g. "0100007F:0050") to IP and port.
func parseHexAddr(s string) (string, string) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return s, ""
	}
	var ip string
	if len(parts[0]) == 8 {
		a := hexToByte(parts[0][6:8])
		b := hexToByte(parts[0][4:6])
		c := hexToByte(parts[0][2:4])
		d := hexToByte(parts[0][0:2])
		ip = fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
	} else {
		ip = parts[0]
	}
	port := fmt.Sprintf("%d", hexToUint16(parts[1]))
	return ip, port
}

func hexToByte(h string) byte {
	var b byte
	fmt.Sscanf(h, "%x", &b)
	return b
}

func hexToUint16(h string) uint16 {
	var v uint16
	fmt.Sscanf(h, "%x", &v)
	return v
}

// tcpState maps hex state code from /proc/net/tcp to human-readable string.
func tcpState(hex string) string {
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

// demoConnections returns placeholder connection data for non-Linux systems.
func demoConnections() []models.Connection {
	return []models.Connection{
		{Protocol: "tcp", LocalIP: "0.0.0.0", LocalPort: "8080", RemoteIP: "0.0.0.0", RemotePort: "0", State: "LISTEN"},
		{Protocol: "tcp", LocalIP: "192.168.1.10", LocalPort: "22", RemoteIP: "192.168.1.50", RemotePort: "54312", State: "ESTABLISHED"},
		{Protocol: "tcp", LocalIP: "192.168.1.10", LocalPort: "443", RemoteIP: "10.0.0.5", RemotePort: "61024", State: "ESTABLISHED"},
		{Protocol: "tcp", LocalIP: "192.168.1.10", LocalPort: "80", RemoteIP: "172.16.0.3", RemotePort: "49871", State: "TIME_WAIT"},
		{Protocol: "tcp", LocalIP: "192.168.1.10", LocalPort: "3306", RemoteIP: "10.0.0.12", RemotePort: "52100", State: "ESTABLISHED"},
		{Protocol: "tcp", LocalIP: "0.0.0.0", LocalPort: "53", RemoteIP: "0.0.0.0", RemotePort: "0", State: "LISTEN"},
	}
}
