package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"kaliwall/internal/logger"
	"kaliwall/internal/threatintel"
)

const blockReasonMaliciousDomain = "Malicious Domain"

// BlockedEvent is a machine-readable blocked-request record.
type BlockedEvent struct {
	EventID    string    `json:"event_id"`
	Timestamp  time.Time `json:"timestamp"`
	Reason     string    `json:"reason"`
	AttackerIP string    `json:"attacker_ip"`
	Domain     string    `json:"domain"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	UserAgent  string    `json:"user_agent"`
	VirusTotal threatintel.DomainURLAssessment `json:"virustotal"`
}

// BlockedEventLogger appends blocked events as JSON lines.
type BlockedEventLogger struct {
	mu   sync.Mutex
	file *os.File
}

// NewBlockedEventLogger creates/open log file used for blocked request events.
func NewBlockedEventLogger(path string) (*BlockedEventLogger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("blocked event log path cannot be empty")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open blocked event log: %w", err)
	}
	return &BlockedEventLogger{file: f}, nil
}

// Close closes the underlying file handle.
func (l *BlockedEventLogger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

// Log appends a blocked event to file in NDJSON format.
func (l *BlockedEventLogger) Log(ev BlockedEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal blocked event: %w", err)
	}
	if _, err := fmt.Fprintf(l.file, "%s\n", line); err != nil {
		return fmt.Errorf("write blocked event: %w", err)
	}
	return nil
}

// FirewallProxy is an HTTP forward proxy with domain-based blocking.
type FirewallProxy struct {
	blocklist *DomainBlocklist
	events    *BlockedEventLogger
	logger    *logger.TrafficLogger
	threat    *threatintel.Service
	transport *http.Transport
}

// NewFirewallProxy builds a proxy handler that blocks malicious hosts.
func NewFirewallProxy(blocklist *DomainBlocklist, eventLogger *BlockedEventLogger, tl *logger.TrafficLogger, ti *threatintel.Service) *FirewallProxy {
	return &FirewallProxy{
		blocklist: blocklist,
		events:    eventLogger,
		logger:    tl,
		threat:    ti,
		transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// DomainStats returns metadata for APIs and diagnostics.
func (p *FirewallProxy) DomainStats() DomainBlocklistStats {
	return p.blocklist.Stats()
}

// DomainList returns current blocked domains.
func (p *FirewallProxy) DomainList() []string {
	return p.blocklist.List()
}

// ReloadDomains forces a manual blocklist reload.
func (p *FirewallProxy) ReloadDomains() (int, error) {
	return p.blocklist.Reload()
}

// StartAutoReload keeps the blocklist in sync with file changes.
func (p *FirewallProxy) StartAutoReload(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				changed, count, err := p.blocklist.ReloadIfChanged()
				if err != nil {
					if p.logger != nil {
						p.logger.Log("ERROR", "-", "-", "HTTP-PROXY", fmt.Sprintf("domain reload failed: %v", err))
					}
					continue
				}
				if changed && p.logger != nil {
					p.logger.Log("CONFIG", "-", "-", "HTTP-PROXY", fmt.Sprintf("malicious domain list reloaded: %d domains", count))
				}
			}
		}
	}()
}

// ServeHTTP handles proxied requests with domain blocking.
func (p *FirewallProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT not supported by this proxy", http.StatusNotImplemented)
		return
	}

	host := targetHost(r)
	if host == "" {
		http.Error(w, "Bad request: missing target host", http.StatusBadRequest)
		return
	}

	if p.blocklist.IsBlocked(host) {
		p.blockRequest(w, r, host)
		return
	}

	proxyReq := r.Clone(r.Context())
	if proxyReq.URL.Scheme == "" {
		proxyReq.URL.Scheme = "http"
	}
	proxyReq.URL.Host = host
	proxyReq.RequestURI = ""

	resp, err := p.transport.RoundTrip(proxyReq)
	if err != nil {
		http.Error(w, "Upstream request failed", http.StatusBadGateway)
		if p.logger != nil {
			p.logger.Log("ERROR", clientIP(r), host, "HTTP-PROXY", fmt.Sprintf("proxy upstream failed: %v", err))
		}
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	if p.logger != nil {
		p.logger.Log("ALLOW", clientIP(r), host, "HTTP", fmt.Sprintf("proxied %s %s", r.Method, r.URL.Path))
	}
}

func (p *FirewallProxy) blockRequest(w http.ResponseWriter, r *http.Request, host string) {
	now := time.Now().UTC()
	eventID := uuid.NewString()
	attacker := clientIP(r)
	requestURL := rawRequestURL(r, host)
	vtAssessment := threatintel.DomainURLAssessment{}
	if p.threat != nil {
		if res, err := p.threat.CheckDomainAndURL(host, requestURL); err != nil {
			vtAssessment = res
			if p.logger != nil {
				p.logger.Log("ERROR", attacker, host, "HTTP", fmt.Sprintf("virustotal lookup failed event_id=%s err=%v", eventID, err))
			}
		} else {
			vtAssessment = res
		}
	}

	ev := BlockedEvent{
		EventID:    eventID,
		Timestamp:  now,
		Reason:     blockReasonMaliciousDomain,
		AttackerIP: attacker,
		Domain:     host,
		Method:     r.Method,
		Path:       r.URL.Path,
		UserAgent:  r.UserAgent(),
		VirusTotal: vtAssessment,
	}
	if p.events != nil {
		_ = p.events.Log(ev)
	}
	if p.logger != nil {
		p.logger.Log("BLOCK", attacker, host, "HTTP", fmt.Sprintf("blocked malicious domain=%s event_id=%s", host, eventID))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = blockPageTmpl.Execute(w, map[string]string{
		"Reason":     blockReasonMaliciousDomain,
		"AttackerIP": attacker,
		"Timestamp":  now.Format(time.RFC3339),
		"EventID":    eventID,
		"Domain":     host,
		"VTDomain":   vtAssessment.Domain.ThreatLevel,
		"VTURL":      vtAssessment.URL.ThreatLevel,
	})
}

func targetHost(r *http.Request) string {
	host := strings.TrimSpace(r.URL.Host)
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host
}

func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func rawRequestURL(r *http.Request, host string) string {
	u := r.URL.String()
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	path := r.URL.RequestURI()
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	return "http://" + host + path
}

var blockPageTmpl = template.Must(template.New("blocked-page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Blocked by KaliWall</title>
  <style>
    :root {
      color-scheme: light;
    }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: "Segoe UI", Tahoma, sans-serif;
      background: radial-gradient(circle at 20% 20%, #fef3c7, #fee2e2 45%, #fecaca 100%);
      color: #7f1d1d;
    }
    .card {
      width: min(680px, 92vw);
      background: rgba(255, 255, 255, 0.93);
      border: 1px solid #fecaca;
      border-radius: 18px;
      box-shadow: 0 12px 30px rgba(127, 29, 29, 0.15);
      padding: 28px;
    }
    h1 {
      margin: 0 0 12px;
      font-size: 1.9rem;
    }
    p {
      margin: 0 0 16px;
      color: #991b1b;
    }
    .meta {
      background: #fff7ed;
      border: 1px solid #fed7aa;
      border-radius: 12px;
      padding: 14px;
      line-height: 1.8;
      color: #7c2d12;
    }
    .label {
      font-weight: 700;
      margin-right: 8px;
    }
  </style>
</head>
<body>
  <main class="card">
		<h1>Blocked by KaliWall</h1>
    <p>The request was denied because the destination is on the malicious domain list.</p>
    <section class="meta">
      <div><span class="label">🚫 Reason:</span>{{.Reason}}</div>
      <div><span class="label">🌍 Attacker IP:</span>{{.AttackerIP}}</div>
      <div><span class="label">⏱ Timestamp:</span>{{.Timestamp}}</div>
      <div><span class="label">🆔 Event ID:</span>{{.EventID}}</div>
      <div><span class="label">Domain:</span>{{.Domain}}</div>
			<div><span class="label">VirusTotal Domain Level:</span>{{.VTDomain}}</div>
			<div><span class="label">VirusTotal URL Level:</span>{{.VTURL}}</div>
    </section>
  </main>
</body>
</html>
`))
