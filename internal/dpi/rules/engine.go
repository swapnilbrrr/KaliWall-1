package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"kaliwall/internal/dpi/types"
)

// Rule describes one DPI matching policy.
type Rule struct {
	ID      string       `json:"id" yaml:"id"`
	Type    string       `json:"type" yaml:"type"`
	Pattern string       `json:"pattern" yaml:"pattern"`
	Action  types.Action `json:"action" yaml:"action"`
	Regex   bool         `json:"regex" yaml:"regex"`

	compiled *regexp.Regexp
	lowerPat []byte
}

// Decision represents first matching rule decision.
type Decision struct {
	Action types.Action
	RuleID string
	Type   string
	Reason string
}

// Engine stores pre-compiled rules.
type Engine struct {
	rules []Rule
}

func LoadFromFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules failed: %w", err)
	}
	var rules []Rule
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("yaml parse failed: %w", err)
		}
	default:
		if err := json.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("json parse failed: %w", err)
		}
	}
	return New(rules)
}

func New(in []Rule) (*Engine, error) {
	rules := make([]Rule, 0, len(in))
	for i, r := range in {
		r.Type = strings.ToLower(strings.TrimSpace(r.Type))
		r.Pattern = strings.TrimSpace(r.Pattern)
		r.Action = types.Action(strings.ToUpper(string(r.Action)))
		if r.ID == "" {
			r.ID = fmt.Sprintf("rule-%03d", i+1)
		}
		if r.Pattern == "" {
			return nil, fmt.Errorf("rule %s empty pattern", r.ID)
		}
		switch r.Action {
		case types.ActionAllow, types.ActionBlock, types.ActionLog:
		default:
			return nil, fmt.Errorf("rule %s invalid action %s", r.ID, r.Action)
		}
		switch r.Type {
		case "payload", "domain", "sni", "http_host", "http_url":
		default:
			return nil, fmt.Errorf("rule %s invalid type %s", r.ID, r.Type)
		}
		if r.Regex {
			rx, err := regexp.Compile(r.Pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %s regex compile failed: %w", r.ID, err)
			}
			r.compiled = rx
		} else {
			r.lowerPat = bytes.ToLower([]byte(r.Pattern))
		}
		rules = append(rules, r)
	}
	return &Engine{rules: rules}, nil
}

func (e *Engine) Evaluate(result types.InspectResult) Decision {
	if e == nil {
		return Decision{Action: types.ActionAllow, Reason: "no_rules"}
	}
	for _, rule := range e.rules {
		if matchRule(rule, result) {
			return Decision{Action: rule.Action, RuleID: rule.ID, Type: rule.Type, Reason: rule.Pattern}
		}
	}
	return Decision{Action: types.ActionAllow, Reason: "default_allow"}
}

func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

func matchRule(rule Rule, result types.InspectResult) bool {
	var target []byte
	switch rule.Type {
	case "payload":
		target = result.Payload
	case "domain":
		t := result.DNSDomain
		if t == "" {
			if result.HTTPHost != "" {
				t = result.HTTPHost
			} else {
				t = result.TLSSNI
			}
		}
		target = []byte(strings.ToLower(t))
	case "sni":
		target = []byte(strings.ToLower(result.TLSSNI))
	case "http_host":
		target = []byte(strings.ToLower(result.HTTPHost))
	case "http_url":
		target = []byte(strings.ToLower(result.HTTPURL))
	}
	if len(target) == 0 {
		return false
	}
	if rule.Regex {
		return rule.compiled.Match(target)
	}
	return bytes.Contains(bytes.ToLower(target), rule.lowerPat)
}
