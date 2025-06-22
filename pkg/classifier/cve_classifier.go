package classifier

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"pod-controller/pkg/common"
	pb "pod-controller/pkg/telemetry"
)

type CVEClassifier struct {
	mappings         []common.CVEMapping
	cveDatabase      map[string]common.CVEMapping
	softwareMap      map[string][]string
	compiledPatterns map[string]*regexp.Regexp
	enabled          bool
	mu               sync.RWMutex
}

func NewCVEClassifier(mappings []common.CVEMapping, enabled bool) *CVEClassifier {
	classifier := &CVEClassifier{
		mappings:         mappings,
		cveDatabase:      make(map[string]common.CVEMapping),
		softwareMap:      make(map[string][]string),
		compiledPatterns: make(map[string]*regexp.Regexp),
		enabled:          enabled,
	}

	if enabled && len(mappings) > 0 {
		classifier.buildDatabase()
	}

	return classifier
}

func (c *CVEClassifier) buildDatabase() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Build CVE database for fast lookup
	for _, mapping := range c.mappings {
		c.cveDatabase[mapping.CVEID] = mapping

		// Build software mapping
		for _, software := range mapping.Software {
			if _, exists := c.softwareMap[software.Name]; !exists {
				c.softwareMap[software.Name] = make([]string, 0)
			}
			c.softwareMap[software.Name] = append(c.softwareMap[software.Name], mapping.CVEID)
		}

		// Pre-compile regex patterns
		for _, eventMatch := range mapping.EventMatches {
			for _, pattern := range eventMatch.CommandPatterns {
				if _, exists := c.compiledPatterns[pattern]; !exists {
					if compiled, err := regexp.Compile(pattern); err == nil {
						c.compiledPatterns[pattern] = compiled
					}
				}
			}
			for _, pattern := range eventMatch.FilePatterns {
				if _, exists := c.compiledPatterns[pattern]; !exists {
					if compiled, err := regexp.Compile(pattern); err == nil {
						c.compiledPatterns[pattern] = compiled
					}
				}
			}
		}
	}
}

func (c *CVEClassifier) ClassifyEvent(event *pb.SecurityEvent) []common.CVEReference {
	if !c.enabled {
		return []common.CVEReference{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	var cveRefs []common.CVEReference

	// Check all CVE mappings for matches
	for _, mapping := range c.cveDatabase {
		if c.matchesMapping(mapping, event) {
			cveRef := common.CVEReference{
				CVEID:       mapping.CVEID,
				Description: fmt.Sprintf("CVE detected based on %s event", pb.EventType_name[int32(event.EventType)]),
				Severity:    mapping.Severity,
				Score:       mapping.Score,
			}

			// Add affected software if available
			for _, software := range mapping.Software {
				cveRef.AffectedSoftware = append(cveRef.AffectedSoftware,
					fmt.Sprintf("%s %s", software.Name, software.VersionRange))
			}

			// Add exploit references if available
			for _, exploit := range mapping.Exploits {
				cveRef.References = append(cveRef.References, exploit.Description)
			}

			cveRefs = append(cveRefs, cveRef)
		}
	}

	return cveRefs
}

func (c *CVEClassifier) matchesMapping(mapping common.CVEMapping, event *pb.SecurityEvent) bool {
	eventType := pb.EventType_name[int32(event.EventType)]

	for _, eventMatch := range mapping.EventMatches {
		if eventMatch.EventType == eventType {
			if c.matchesEventPattern(eventMatch, event) {
				return true
			}
		}
	}

	return false
}

func (c *CVEClassifier) matchesEventPattern(eventMatch common.EventMatch, event *pb.SecurityEvent) bool {
	// Check command patterns
	for _, pattern := range eventMatch.CommandPatterns {
		if c.matchesPattern(pattern, event.Command) {
			if c.matchesConditions(eventMatch.Conditions, event) {
				return true
			}
		}
	}

	// Check file patterns
	for _, pattern := range eventMatch.FilePatterns {
		if c.matchesPattern(pattern, event.FilePath) {
			if c.matchesConditions(eventMatch.Conditions, event) {
				return true
			}
		}
	}

	// Check network patterns
	for _, netPattern := range eventMatch.NetworkPatterns {
		if c.matchesNetworkPattern(netPattern, event) {
			if c.matchesConditions(eventMatch.Conditions, event) {
				return true
			}
		}
	}

	// If no specific patterns, check conditions only
	if len(eventMatch.CommandPatterns) == 0 && len(eventMatch.FilePatterns) == 0 && len(eventMatch.NetworkPatterns) == 0 {
		return c.matchesConditions(eventMatch.Conditions, event)
	}

	return false
}

func (c *CVEClassifier) matchesPattern(pattern, text string) bool {
	if pattern == "" || text == "" {
		return false
	}

	// Try compiled regex first
	if compiled, exists := c.compiledPatterns[pattern]; exists {
		return compiled.MatchString(text)
	}

	// Fallback to simple string matching
	return strings.Contains(strings.ToLower(text), strings.ToLower(pattern))
}

func (c *CVEClassifier) matchesNetworkPattern(pattern common.NetworkPattern, event *pb.SecurityEvent) bool {
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

func (c *CVEClassifier) matchesConditions(conditions []common.MatchCondition, event *pb.SecurityEvent) bool {
	if len(conditions) == 0 {
		return true
	}

	for _, condition := range conditions {
		if !c.evaluateCondition(condition, event) {
			return false
		}
	}

	return true
}

func (c *CVEClassifier) evaluateCondition(condition common.MatchCondition, event *pb.SecurityEvent) bool {
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

func (c *CVEClassifier) GetCVEsBySoftware(software string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if cves, exists := c.softwareMap[software]; exists {
		return cves
	}
	return []string{}
}

func (c *CVEClassifier) ReloadMappings(mappings []common.CVEMapping, enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mappings = mappings
	c.enabled = enabled
	c.cveDatabase = make(map[string]common.CVEMapping)
	c.softwareMap = make(map[string][]string)
	c.compiledPatterns = make(map[string]*regexp.Regexp)

	if enabled && len(mappings) > 0 {
		c.buildDatabase()
	}

	return nil
}

func (c *CVEClassifier) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

func (c *CVEClassifier) GetDatabaseSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cveDatabase)
}
