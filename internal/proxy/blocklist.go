package proxy

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// DomainBlocklist holds malicious domains loaded from a text file.
type DomainBlocklist struct {
	mu          sync.RWMutex
	path        string
	domains     map[string]struct{}
	lastLoad    time.Time
	lastModTime time.Time
}

// DomainBlocklistStats describes current state for observability and APIs.
type DomainBlocklistStats struct {
	Path          string    `json:"path"`
	DomainCount   int       `json:"domain_count"`
	LastLoadedAt  time.Time `json:"last_loaded_at"`
	LastFileModAt time.Time `json:"last_file_mod_at"`
}

// NewDomainBlocklist creates a domain blocklist and performs the initial load.
func NewDomainBlocklist(path string) (*DomainBlocklist, error) {
	bl := &DomainBlocklist{
		path:    strings.TrimSpace(path),
		domains: make(map[string]struct{}),
	}
	if bl.path == "" {
		return nil, fmt.Errorf("malicious domains path cannot be empty")
	}
	if _, err := bl.Reload(); err != nil {
		return nil, err
	}
	return bl, nil
}

// ReloadIfChanged reloads the blocklist when the file modification time changed.
func (d *DomainBlocklist) ReloadIfChanged() (bool, int, error) {
	st, err := os.Stat(d.path)
	if err != nil {
		return false, 0, err
	}
	mod := st.ModTime()

	d.mu.RLock()
	unchanged := !mod.After(d.lastModTime)
	d.mu.RUnlock()
	if unchanged {
		return false, d.Count(), nil
	}

	count, err := d.Reload()
	if err != nil {
		return false, 0, err
	}
	return true, count, nil
}

// Reload forces a complete reload from disk.
func (d *DomainBlocklist) Reload() (int, error) {
	f, err := os.Open(d.path)
	if err != nil {
		return 0, fmt.Errorf("open malicious domains file: %w", err)
	}
	defer f.Close()

	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := normalizeDomain(line)
		if domain == "" {
			continue
		}
		seen[domain] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan malicious domains file: %w", err)
	}

	st, err := os.Stat(d.path)
	if err != nil {
		return 0, fmt.Errorf("stat malicious domains file: %w", err)
	}

	d.mu.Lock()
	d.domains = seen
	d.lastLoad = time.Now().UTC()
	d.lastModTime = st.ModTime().UTC()
	count := len(d.domains)
	d.mu.Unlock()

	return count, nil
}

// IsBlocked reports whether the host matches a blocked domain or subdomain.
func (d *DomainBlocklist) IsBlocked(host string) bool {
	host = normalizeDomain(host)
	if host == "" {
		return false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if _, ok := d.domains[host]; ok {
		return true
	}
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		suffix := strings.Join(parts[i:], ".")
		if _, ok := d.domains[suffix]; ok {
			return true
		}
	}
	return false
}

// List returns the sorted set of blocked domains.
func (d *DomainBlocklist) List() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, 0, len(d.domains))
	for domain := range d.domains {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

// Count returns number of loaded domains.
func (d *DomainBlocklist) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.domains)
}

// Stats returns current metadata for the blocklist.
func (d *DomainBlocklist) Stats() DomainBlocklistStats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return DomainBlocklistStats{
		Path:          d.path,
		DomainCount:   len(d.domains),
		LastLoadedAt:  d.lastLoad,
		LastFileModAt: d.lastModTime,
	}
}

func normalizeDomain(raw string) string {
	d := strings.TrimSpace(strings.ToLower(raw))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if idx := strings.IndexByte(d, '/'); idx >= 0 {
		d = d[:idx]
	}
	if idx := strings.IndexByte(d, ':'); idx >= 0 {
		d = d[:idx]
	}
	d = strings.TrimSuffix(d, ".")
	return d
}
