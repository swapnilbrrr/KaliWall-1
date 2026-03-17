package rules

import (
	"testing"

	"kaliwall/internal/dpi/types"
)

func TestRuleEngineHTTPAndDNS(t *testing.T) {
	engine, err := New([]Rule{
		{ID: "r1", Type: "payload", Pattern: "union select", Action: types.ActionBlock},
		{ID: "r2", Type: "domain", Pattern: "bad.com", Action: types.ActionBlock},
	})
	if err != nil {
		t.Fatalf("failed to build rules: %v", err)
	}

	httpResult := types.InspectResult{Payload: []byte("GET /?q=union select user HTTP/1.1\r\nHost: test\r\n\r\n")}
	if d := engine.Evaluate(httpResult); d.Action != types.ActionBlock {
		t.Fatalf("expected BLOCK for HTTP payload, got %s", d.Action)
	}

	dnsResult := types.InspectResult{DNSDomain: "api.bad.com"}
	if d := engine.Evaluate(dnsResult); d.Action != types.ActionBlock {
		t.Fatalf("expected BLOCK for DNS domain, got %s", d.Action)
	}
}
