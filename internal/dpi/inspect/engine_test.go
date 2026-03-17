package inspect

import (
	"testing"
	"time"

	"kaliwall/internal/dpi/types"
)

func TestInspectHTTPAttackPattern(t *testing.T) {
	eng := New()
	payload := types.AppPayload{
		Timestamp: time.Now(),
		Tuple: types.FiveTuple{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1234, DstPort: 80, Protocol: "tcp"},
		Payload: []byte("GET /index.php?cmd=ls HTTP/1.1\r\nHost: victim.local\r\nUser-Agent: test\r\n\r\n"),
	}
	res := eng.Inspect(payload)
	if res.HTTPMethod != "GET" || res.HTTPHost != "victim.local" {
		t.Fatalf("failed to parse HTTP fields: method=%q host=%q", res.HTTPMethod, res.HTTPHost)
	}
	found := false
	for _, d := range res.Detections {
		if d == "payload:cmd=" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected cmd= detection")
	}
}

func TestInspectDNSDomain(t *testing.T) {
	eng := New()
	res := eng.Inspect(types.AppPayload{
		Timestamp: time.Now(),
		Tuple:     types.FiveTuple{Protocol: "udp"},
		DNSQuery:  "bad.com.",
	})
	if res.DNSDomain != "bad.com" {
		t.Fatalf("unexpected domain extraction: %q", res.DNSDomain)
	}
}
