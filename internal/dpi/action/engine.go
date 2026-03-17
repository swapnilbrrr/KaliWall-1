package action

import (
	"encoding/json"
	"fmt"
	"log"

	"kaliwall/internal/dpi/rules"
	"kaliwall/internal/dpi/types"
	"kaliwall/internal/logger"
	"kaliwall/internal/models"
)

// Engine handles final decision side effects.
type Engine struct {
	trafficLog *logger.TrafficLogger
}

func New(trafficLog *logger.TrafficLogger) *Engine {
	return &Engine{trafficLog: trafficLog}
}

func (e *Engine) Handle(result types.InspectResult, decision rules.Decision) {
	entry := map[string]interface{}{
		"ts":       result.Timestamp,
		"src_ip":   result.Tuple.SrcIP,
		"dst_ip":   result.Tuple.DstIP,
		"src_port": result.Tuple.SrcPort,
		"dst_port": result.Tuple.DstPort,
		"protocol": result.Tuple.Protocol,
		"action":   decision.Action,
		"rule_id":  decision.RuleID,
		"rule_type": decision.Type,
		"reason":   decision.Reason,
		"http_host": result.HTTPHost,
		"http_url": result.HTTPURL,
		"dns_domain": result.DNSDomain,
		"tls_sni":  result.TLSSNI,
		"signals":  result.Detections,
	}
	b, _ := json.Marshal(entry)

	switch decision.Action {
	case types.ActionBlock:
		log.Printf("DPI BLOCK %s", b)
		if e.trafficLog != nil {
			e.trafficLog.Log("BLOCK", result.Tuple.SrcIP, result.Tuple.DstIP, result.Tuple.Protocol, fmt.Sprintf("dpi:block:%s", decision.Reason))
			e.trafficLog.EmitFirewallEvent(models.FirewallEvent{
				EventType: "blocked_packet",
				Backend:   "dpi",
				Action:    "BLOCK",
				SrcIP:     result.Tuple.SrcIP,
				DstIP:     result.Tuple.DstIP,
				Protocol:  result.Tuple.Protocol,
				SrcPort:   fmt.Sprintf("%d", result.Tuple.SrcPort),
				DstPort:   fmt.Sprintf("%d", result.Tuple.DstPort),
				Detail:    "dpi:" + decision.Reason,
				Severity:  "critical",
			})
		}
	case types.ActionLog:
		log.Printf("DPI LOG %s", b)
		if e.trafficLog != nil {
			e.trafficLog.Log("LOG", result.Tuple.SrcIP, result.Tuple.DstIP, result.Tuple.Protocol, fmt.Sprintf("dpi:log:%s", decision.Reason))
		}
	default:
		// Allow path intentionally has no side-effect logging to reduce hot-path overhead.
	}
}
