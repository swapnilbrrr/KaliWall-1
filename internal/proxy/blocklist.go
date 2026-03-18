package proxy

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
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
	if _, ok := d.domains["*."+host]; ok {
		return true
	}
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		suffix := strings.Join(parts[i:], ".")
		if _, ok := d.domains[suffix]; ok {
			return true
		}
		if _, ok := d.domains["*."+suffix]; ok {
			return true
		}
	}
	return false
}

// AddDomain persists and loads a domain into the blocklist.
func (d *DomainBlocklist) AddDomain(raw string) (bool, string, error) {
	domain := normalizeDomain(raw)
	if strings.HasPrefix(strings.TrimSpace(strings.ToLower(raw)), "*.") {
		domain = "*." + domain
	}
	if domain == "" {
		return false, "", fmt.Errorf("domain cannot be empty")
	}

	d.mu.RLock()
	_, exists := d.domains[domain]
	d.mu.RUnlock()
	if exists {
		return false, domain, nil
	}

	f, err := os.OpenFile(d.path, os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return false, "", fmt.Errorf("open malicious domains file for append: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, domain); err != nil {
		return false, "", fmt.Errorf("append domain to malicious list: %w", err)
	}
	if _, err := d.Reload(); err != nil {
		return false, "", err
	}
	return true, domain, nil
}

// RemoveDomain removes a domain from the persisted blocklist file.
func (d *DomainBlocklist) RemoveDomain(raw string) (bool, string, error) {
	domain := normalizeDomain(raw)
	if strings.HasPrefix(strings.TrimSpace(strings.ToLower(raw)), "*.") {
		domain = "*." + domain
	}
	if domain == "" {
		return false, "", fmt.Errorf("domain cannot be empty")
	}

	src, err := os.Open(d.path)
	if err != nil {
		return false, "", fmt.Errorf("open malicious domains file for remove: %w", err)
	}
	defer src.Close()

	tmpPath := filepath.Clean(d.path + ".tmp")
	dst, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if err != nil {
		return false, "", fmt.Errorf("create temporary malicious domains file: %w", err)
	}

	removed := false
	scanner := bufio.NewScanner(src)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if _, err := fmt.Fprintln(dst, line); err != nil {
				dst.Close()
				return false, "", fmt.Errorf("write preserved line: %w", err)
			}
			continue
		}
		if normalizeDomain(trimmed) == strings.TrimPrefix(domain, "*.") || trimmed == domain {
			removed = true
			continue
		}
		if _, err := fmt.Fprintln(dst, line); err != nil {
			dst.Close()
			return false, "", fmt.Errorf("write domain line: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		dst.Close()
		return false, "", fmt.Errorf("scan malicious domains file: %w", err)
	}
	if err := dst.Close(); err != nil {
		return false, "", fmt.Errorf("close temporary malicious domains file: %w", err)
	}
	if err := os.Rename(tmpPath, d.path); err != nil {
		return false, "", fmt.Errorf("replace malicious domains file: %w", err)
	}
	if _, err := d.Reload(); err != nil {
		return false, "", err
	}
	return removed, domain, nil
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
	d = strings.TrimPrefix(d, "*.")
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
