package policy

import (
	"encoding/json"
	"log"

	pb "github.com/danushkastanley/rasp-controller/pkg/api/proto"
	"github.com/danushkastanley/rasp-controller/internal/detection"
)

// Action represents a response action to a security event
type Action string

const (
	ActionAllow     Action = "ALLOW"
	ActionLog       Action = "LOG"
	ActionAlert     Action = "ALERT"
	ActionBlock     Action = "BLOCK"
	ActionQuarantine Action = "QUARANTINE"
)

// Rule represents a security policy rule
type Rule struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	EventTypes  []pb.EventType         `json:"event_types"`
	MinThreat   detection.ThreatLevel  `json:"min_threat"`
	Action      Action                 `json:"action"`
	Conditions  map[string]interface{} `json:"conditions"`
}

// Engine handles policy evaluation and enforcement
type Engine struct {
	rules []Rule
}

// NewEngine creates a new policy engine instance
func NewEngine() *Engine {
	return &Engine{
		rules: defaultRules(),
	}
}

// LoadPolicy loads policy rules from a configuration file
func (e *Engine) LoadPolicy(config []byte) error {
	var rules []Rule
	if err := json.Unmarshal(config, &rules); err != nil {
		return err
	}
	e.rules = rules
	return nil
}

// Evaluate applies policy rules to an event and returns the appropriate action
func (e *Engine) Evaluate(event *pb.SecurityEvent, threatLevel detection.ThreatLevel) Action {
	for _, rule := range e.rules {
		if e.matchesRule(event, threatLevel, rule) {
			log.Printf("Policy rule '%s' matched: taking action %s", rule.Name, rule.Action)
			return rule.Action
		}
	}
	return ActionAllow
}

// matchesRule checks if an event matches a policy rule
func (e *Engine) matchesRule(event *pb.SecurityEvent, threatLevel detection.ThreatLevel, rule Rule) bool {
	// Check threat level threshold
	if threatLevel < rule.MinThreat {
		return false
	}

	// Check event type
	eventTypeMatch := false
	for _, et := range rule.EventTypes {
		if event.EventType == et {
			eventTypeMatch = true
			break
		}
	}
	if !eventTypeMatch && len(rule.EventTypes) > 0 {
		return false
	}

	// Check additional conditions
	// TODO: Implement more sophisticated condition matching
	return true
}

// defaultRules returns the default set of policy rules
func defaultRules() []Rule {
	return []Rule{
		{
			Name:        "Block High Threats",
			Description: "Block any high-threat events",
			EventTypes:  []pb.EventType{},  // Apply to all event types
			MinThreat:   detection.ThreatLevelHigh,
			Action:      ActionBlock,
		},
		{
			Name:        "Alert on Medium Threats",
			Description: "Generate alerts for medium-threat events",
			EventTypes:  []pb.EventType{},
			MinThreat:   detection.ThreatLevelMedium,
			Action:      ActionAlert,
		},
		{
			Name:        "Log Low Threats",
			Description: "Log low-threat events",
			EventTypes:  []pb.EventType{},
			MinThreat:   detection.ThreatLevelLow,
			Action:      ActionLog,
		},
	}
}

// Future enhancements:
// TODO: Add policy versioning
// TODO: Add policy validation
// TODO: Add policy hot-reload
// TODO: Add policy audit logging
// TODO: Add policy effectiveness metrics
// TODO: Add policy conflict resolution
