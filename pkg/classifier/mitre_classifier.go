package classifier

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"pod-controller/pkg/common"
	pb "pod-controller/pkg/telemetry"
)

type MitreClassifier struct {
	techniques       []common.TechniqueMapping
	tactics          []common.TacticMapping
	dataSources      []common.DataSourceMapping
	techniqueMap     map[string]common.TechniqueMapping
	tacticMap        map[string]common.TacticMapping
	compiledPatterns map[string]*regexp.Regexp
	enabled          bool
	version          string
	mu               sync.RWMutex
}

func NewMitreClassifier(techniques []common.TechniqueMapping, tactics []common.TacticMapping, dataSources []common.DataSourceMapping, enabled bool, version string) *MitreClassifier {
	classifier := &MitreClassifier{
		techniques:       techniques,
		tactics:          tactics,
		dataSources:      dataSources,
		techniqueMap:     make(map[string]common.TechniqueMapping),
		tacticMap:        make(map[string]common.TacticMapping),
		compiledPatterns: make(map[string]*regexp.Regexp),
		enabled:          enabled,
		version:          version,
	}

	if enabled && len(techniques) > 0 {
		classifier.buildDatabase()
	}

	return classifier
}

func (m *MitreClassifier) buildDatabase() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Build technique mapping for fast lookup
	for _, technique := range m.techniques {
		m.techniqueMap[technique.TechniqueID] = technique

		// Pre-compile regex patterns for better performance
		for _, eventMatch := range technique.EventMatches {
			for _, pattern := range eventMatch.CommandPatterns {
				if _, exists := m.compiledPatterns[pattern]; !exists {
					if compiled, err := regexp.Compile(pattern); err == nil {
						m.compiledPatterns[pattern] = compiled
					}
				}
			}
			for _, pattern := range eventMatch.FilePatterns {
				if _, exists := m.compiledPatterns[pattern]; !exists {
					if compiled, err := regexp.Compile(pattern); err == nil {
						m.compiledPatterns[pattern] = compiled
					}
				}
			}
		}
	}

	// Build tactic mapping
	for _, tactic := range m.tactics {
		m.tacticMap[tactic.Name] = tactic
	}
}

func (m *MitreClassifier) ClassifyEvent(event *pb.SecurityEvent) []common.AttackTechnique {
	if !m.enabled {
		return []common.AttackTechnique{}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var techniques []common.AttackTechnique

	// Check all technique mappings for matches
	for _, techniqueMapping := range m.techniqueMap {
		if m.matchesTechnique(techniqueMapping, event) {
			confidence := m.calculateConfidence(techniqueMapping, event)

			technique := common.AttackTechnique{
				TechniqueID:   techniqueMapping.TechniqueID,
				TechniqueName: techniqueMapping.TechniqueName,
				Tactic:        techniqueMapping.Tactic,
				Confidence:    confidence,
				DataSources:   m.getDataSourcesForEventType(pb.EventType_name[int32(event.EventType)]),
			}

			// Add sub-techniques if available
			if len(techniqueMapping.SubTechniques) > 0 {
				technique.SubTechnique = strings.Join(techniqueMapping.SubTechniques, ", ")
			}

			techniques = append(techniques, technique)
		}
	}

	return techniques
}

func (m *MitreClassifier) matchesTechnique(technique common.TechniqueMapping, event *pb.SecurityEvent) bool {
	eventType := pb.EventType_name[int32(event.EventType)]

	for _, eventMatch := range technique.EventMatches {
		if eventMatch.EventType == eventType {
			if m.matchesEventPattern(eventMatch, event) {
				return true
			}
		}
	}

	return false
}

func (m *MitreClassifier) matchesEventPattern(eventMatch common.EventMatch, event *pb.SecurityEvent) bool {
	// Check command patterns
	for _, pattern := range eventMatch.CommandPatterns {
		if m.matchesPattern(pattern, event.Command) {
			if m.matchesConditions(eventMatch.Conditions, event) {
				return true
			}
		}
	}

	// Check file patterns
	for _, pattern := range eventMatch.FilePatterns {
		if m.matchesPattern(pattern, event.FilePath) {
			if m.matchesConditions(eventMatch.Conditions, event) {
				return true
			}
		}
	}

	// Check network patterns
	for _, netPattern := range eventMatch.NetworkPatterns {
		if m.matchesNetworkPattern(netPattern, event) {
			if m.matchesConditions(eventMatch.Conditions, event) {
				return true
			}
		}
	}

	// If no specific patterns, check conditions only
	if len(eventMatch.CommandPatterns) == 0 && len(eventMatch.FilePatterns) == 0 && len(eventMatch.NetworkPatterns) == 0 {
		return m.matchesConditions(eventMatch.Conditions, event)
	}

	return false
}

func (m *MitreClassifier) matchesPattern(pattern, text string) bool {
	if pattern == "" || text == "" {
		return false
	}

	// Try compiled regex first
	if compiled, exists := m.compiledPatterns[pattern]; exists {
		return compiled.MatchString(text)
	}

	// Fallback to simple string matching
	return strings.Contains(strings.ToLower(text), strings.ToLower(pattern))
}

func (m *MitreClassifier) matchesNetworkPattern(pattern common.NetworkPattern, event *pb.SecurityEvent) bool {
	// Check port matching
	if len(pattern.Ports) > 0 {
		foundPort := false
		for _, port := range pattern.Ports {
			if int32(port) == event.DestinationPort || int32(port) == event.SourcePort {
				foundPort = true
				break
			}
		}
		if !foundPort {
			return false
		}
	}

	// Check destination ranges (simplified implementation)
	if len(pattern.DestinationRanges) > 0 {
		for _, rangePattern := range pattern.DestinationRanges {
			if strings.Contains(event.DestinationIp, rangePattern) {
				return true
			}
		}
		return false
	}

	return true
}

func (m *MitreClassifier) matchesConditions(conditions []common.MatchCondition, event *pb.SecurityEvent) bool {
	if len(conditions) == 0 {
		return true
	}

	for _, condition := range conditions {
		if !m.evaluateCondition(condition, event) {
			return false
		}
	}

	return true
}

func (m *MitreClassifier) evaluateCondition(condition common.MatchCondition, event *pb.SecurityEvent) bool {
	var fieldValue string

	switch condition.Field {
	case "uid":
		fieldValue = fmt.Sprintf("%d", event.Uid)
	case "gid":
		fieldValue = fmt.Sprintf("%d", event.Gid)
	case "pid":
		fieldValue = fmt.Sprintf("%d", event.Pid)
	case "command":
		fieldValue = event.Command
	case "file_path":
		fieldValue = event.FilePath
	case "destination_ip":
		fieldValue = event.DestinationIp
	case "destination_port":
		fieldValue = fmt.Sprintf("%d", event.DestinationPort)
	case "source_port":
		fieldValue = fmt.Sprintf("%d", event.SourcePort)
	case "is_root":
		fieldValue = fmt.Sprintf("%t", event.Uid == 0)
	default:
		return false
	}

	switch condition.Operator {
	case "equals":
		return fieldValue == condition.Value
	case "not_equals":
		return fieldValue != condition.Value
	case "contains":
		return strings.Contains(strings.ToLower(fieldValue), strings.ToLower(condition.Value))
	case "matches":
		if compiled, err := regexp.Compile(condition.Value); err == nil {
			return compiled.MatchString(fieldValue)
		}
		return false
	default:
		return false
	}
}

func (m *MitreClassifier) calculateConfidence(technique common.TechniqueMapping, event *pb.SecurityEvent) float64 {
	baseConfidence := technique.Confidence

	// Adjust confidence based on event characteristics
	confidenceAdjustment := 0.0

	// Higher confidence for root processes
	if event.Uid == 0 {
		confidenceAdjustment += 0.1
	}

	// Higher confidence for external network activity
	if event.EventType == pb.EventType_CONNECT && event.DestinationIp != "" {
		if !strings.HasPrefix(event.DestinationIp, "192.168.") &&
			!strings.HasPrefix(event.DestinationIp, "10.") &&
			!strings.HasPrefix(event.DestinationIp, "172.") &&
			event.DestinationIp != "127.0.0.1" {
			confidenceAdjustment += 0.15
		}
	}

	// Higher confidence for sensitive file access
	if event.EventType == pb.EventType_OPEN {
		if strings.HasPrefix(event.FilePath, "/etc/") ||
			strings.HasPrefix(event.FilePath, "/root/") ||
			strings.HasPrefix(event.FilePath, "/var/log/") {
			confidenceAdjustment += 0.1
		}
	}

	// Ensure confidence stays within valid range
	finalConfidence := baseConfidence + confidenceAdjustment
	if finalConfidence > 1.0 {
		finalConfidence = 1.0
	}
	if finalConfidence < 0.0 {
		finalConfidence = 0.0
	}

	return finalConfidence
}

func (m *MitreClassifier) getDataSourcesForEventType(eventType string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, dataSource := range m.dataSources {
		for _, et := range dataSource.EventTypes {
			if et == eventType {
				return []string{dataSource.Name}
			}
		}
	}

	return []string{"Process Monitoring", "System Monitoring"}
}

func (m *MitreClassifier) GetTechniquesByTactic(tacticName string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if tactic, exists := m.tacticMap[tacticName]; exists {
		return tactic.Techniques
	}

	return []string{}
}

func (m *MitreClassifier) ReloadData(techniques []common.TechniqueMapping, tactics []common.TacticMapping, dataSources []common.DataSourceMapping, enabled bool, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.techniques = techniques
	m.tactics = tactics
	m.dataSources = dataSources
	m.enabled = enabled
	m.version = version
	m.techniqueMap = make(map[string]common.TechniqueMapping)
	m.tacticMap = make(map[string]common.TacticMapping)
	m.compiledPatterns = make(map[string]*regexp.Regexp)

	if enabled && len(techniques) > 0 {
		m.buildDatabase()
	}

	return nil
}

func (m *MitreClassifier) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

func (m *MitreClassifier) GetVersion() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}

func (m *MitreClassifier) GetTechniqueCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.techniqueMap)
}
