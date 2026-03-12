// Package models defines data structures used across KaliWall.
package models

import "time"

// Rule represents a single firewall rule.
type Rule struct {
	ID        string    `json:"id"`
	Chain     string    `json:"chain"`     // INPUT, OUTPUT, FORWARD
	Protocol  string    `json:"protocol"`  // tcp, udp, icmp, all
	SrcIP     string    `json:"src_ip"`    // Source IP/CIDR ("any" for all)
	DstIP     string    `json:"dst_ip"`    // Destination IP/CIDR ("any" for all)
	SrcPort   string    `json:"src_port"`  // Source port ("any" for all)
	DstPort   string    `json:"dst_port"`  // Destination port ("any" for all)
	Action    string    `json:"action"`    // ACCEPT, DROP, REJECT
	Comment   string    `json:"comment"`   // Human-readable description
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// RuleRequest is the payload for creating/updating a rule via the API.
type RuleRequest struct {
	Chain    string `json:"chain"`
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  string `json:"src_port"`
	DstPort  string `json:"dst_port"`
	Action   string `json:"action"`
	Comment  string `json:"comment"`
	Enabled  bool   `json:"enabled"`
}

// TrafficEntry represents a single logged traffic event.
type TrafficEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"` // ALLOW, BLOCK, REJECT
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	Protocol  string    `json:"protocol"`
	Detail    string    `json:"detail"`
}

// Connection represents an active network connection (from /proc/net).
type Connection struct {
	Protocol string `json:"protocol"`
	LocalIP  string `json:"local_ip"`
	LocalPort string `json:"local_port"`
	RemoteIP  string `json:"remote_ip"`
	RemotePort string `json:"remote_port"`
	State     string `json:"state"`
}

// DashboardStats holds summary statistics for the web UI dashboard.
type DashboardStats struct {
	TotalRules        int `json:"total_rules"`
	ActiveRules       int `json:"active_rules"`
	BlockedToday      int `json:"blocked_today"`
	AllowedToday      int `json:"allowed_today"`
	ActiveConnections int `json:"active_connections"`
}

// APIResponse wraps all API responses with a consistent envelope.
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}
