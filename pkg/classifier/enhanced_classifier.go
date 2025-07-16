package classifier

import (
	"fmt"
	"sync"
	"time"

	"pod-controller/pkg/common"
	pb "pod-controller/pkg/telemetry"
)

type EnhancedClassifier struct {
	baseClassifier   EventClassifierInterface
	mitreClassifier  *MitreClassifier
	cveClassifier    *CVEClassifier
	customClassifier *CustomFrameworkClassifier
	threatIntel      *ThreatIntelClassifier

	// Configuration
	thresholds      map[string]float64
	enabledFeatures map[string]bool

	// Metrics
	metrics     map[string]interface{}
	metricsLock sync.RWMutex

	mu sync.RWMutex
}

type CustomFrameworkClassifier struct {
	rules   map[string]common.CustomFrameworkRule
	enabled bool
	mu      sync.RWMutex
}

type ThreatIntelClassifier struct {
	sources  []common.ThreatIntelSource
	mappings []common.ThreatIntelMapping
	enabled  bool
	mu       sync.RWMutex
}

func NewEnhancedClassifier(
	baseClassifier EventClassifierInterface,
	mitreRules []common.TechniqueMapping,
	mitreTactics []common.TacticMapping,
	mitreDataSources []common.DataSourceMapping,
	mitreEnabled bool,
	mitreVersion string,
	cveMappings []common.CVEMapping,
	cveEnabled bool,
	customRules map[string]common.CustomFrameworkRule,
	customEnabled bool,
	threatSources []common.ThreatIntelSource,
	threatMappings []common.ThreatIntelMapping,
	threatEnabled bool,
) *EnhancedClassifier {

	classifier := &EnhancedClassifier{
		baseClassifier: baseClassifier,
		thresholds: map[string]float64{
			"mitre_confidence_threshold":  0.5,
			"cve_score_threshold":         5.0,
			"custom_confidence_threshold": 0.6,
		},
		enabledFeatures: map[string]bool{
			"mitre_classification":  mitreEnabled,
			"cve_classification":    cveEnabled,
			"custom_classification": customEnabled,
			"threat_intel":          threatEnabled,
		},
		metrics: make(map[string]interface{}),
	}

	// Initialize component classifiers
	classifier.mitreClassifier = NewMitreClassifier(
		mitreRules, mitreTactics, mitreDataSources, mitreEnabled, mitreVersion,
	)

	classifier.cveClassifier = NewCVEClassifier(cveMappings, cveEnabled)

	classifier.customClassifier = &CustomFrameworkClassifier{
		rules:   customRules,
		enabled: customEnabled,
	}

	classifier.threatIntel = &ThreatIntelClassifier{
		sources:  threatSources,
		mappings: threatMappings,
		enabled:  threatEnabled,
	}

	return classifier
}

// ClassifyEvent implements EventClassifierInterface
func (e *EnhancedClassifier) ClassifyEvent(event *pb.SecurityEvent) (common.Severity, string) {
	// Use base classifier for backward compatibility
	return e.baseClassifier.ClassifyEvent(event)
}

// ClassifyEventEnhanced implements EnhancedClassifierInterface
func (e *EnhancedClassifier) ClassifyEventEnhanced(event *pb.SecurityEvent) (*common.ClassificationResult, error) {
	e.mu.RLock()
	enabledFeatures := e.enabledFeatures
	thresholds := e.thresholds
	e.mu.RUnlock()

	result := &common.ClassificationResult{
		AttackTechniques: []common.AttackTechnique{},
		CVEReferences:    []common.CVEReference{},
		ThreatIntel:      nil,
		Classifications:  []common.Classification{},
	}

	// MITRE ATT&CK Classification
	if enabledFeatures["mitre_classification"] {
		techniques := e.mitreClassifier.ClassifyEvent(event)
		for _, technique := range techniques {
			if technique.Confidence >= thresholds["mitre_confidence_threshold"] {
				result.AttackTechniques = append(result.AttackTechniques, technique)

				// Add to general classifications
				result.Classifications = append(result.Classifications, common.Classification{
					Framework:   "MITRE",
					Category:    technique.Tactic,
					Subcategory: technique.TechniqueName,
					Confidence:  technique.Confidence,
					Metadata: map[string]string{
						"technique_id": technique.TechniqueID,
						"data_sources": fmt.Sprintf("%v", technique.DataSources),
					},
				})
			}
		}
		e.updateMetrics("mitre_classifications_performed", 1)
	}

	// CVE Classification
	if enabledFeatures["cve_classification"] {
		cves := e.cveClassifier.ClassifyEvent(event)
		for _, cve := range cves {
			if cve.Score >= thresholds["cve_score_threshold"] {
				result.CVEReferences = append(result.CVEReferences, cve)

				// Add to general classifications
				result.Classifications = append(result.Classifications, common.Classification{
					Framework:   "CVE",
					Category:    "Vulnerability",
					Subcategory: cve.CVEID,
					Confidence:  e.calculateCVEConfidence(cve.Score),
					Metadata: map[string]string{
						"cve_id":      cve.CVEID,
						"cvss_score":  fmt.Sprintf("%.1f", cve.Score),
						"severity":    cve.Severity,
						"description": cve.Description,
					},
				})
			}
		}
		e.updateMetrics("cve_classifications_performed", 1)
	}

	// Custom Framework Classification
	if enabledFeatures["custom_classification"] {
		customClassifications := e.customClassifier.ClassifyEvent(event)
		for _, classification := range customClassifications {
			if classification.Confidence >= thresholds["custom_confidence_threshold"] {
				result.Classifications = append(result.Classifications, classification)
			}
		}
		e.updateMetrics("custom_classifications_performed", 1)
	}

	// Threat Intelligence
	if enabledFeatures["threat_intel"] {
		threatIntel := e.threatIntel.ClassifyEvent(event)
		if threatIntel != nil {
			result.ThreatIntel = threatIntel

			// Add to general classifications
			result.Classifications = append(result.Classifications, common.Classification{
				Framework:  "ThreatIntel",
				Category:   "Threat Actor",
				Confidence: 0.8, // Default confidence for threat intel
				Metadata: map[string]string{
					"threat_actors": fmt.Sprintf("%v", threatIntel.ThreatActors),
					"campaigns":     fmt.Sprintf("%v", threatIntel.Campaigns),
					"malware":       fmt.Sprintf("%v", threatIntel.Malware),
				},
			})
		}
		e.updateMetrics("threat_intel_classifications_performed", 1)
	}

	e.updateMetrics("total_enhanced_classifications_performed", 1)
	return result, nil
}

func (e *EnhancedClassifier) calculateCVEConfidence(score float64) float64 {
	// Convert CVSS score (0-10) to confidence (0-1)
	// Higher CVSS score = higher confidence
	confidence := score / 10.0
	if confidence > 1.0 {
		confidence = 1.0
	}
	return confidence
}

func (e *EnhancedClassifier) updateMetrics(key string, increment int) {
	e.metricsLock.Lock()
	defer e.metricsLock.Unlock()

	if current, exists := e.metrics[key]; exists {
		if currentInt, ok := current.(int); ok {
			e.metrics[key] = currentInt + increment
		}
	} else {
		e.metrics[key] = increment
	}

	e.metrics["last_updated"] = time.Now()
}

// ReloadAllRules implements EnhancedClassifierInterface
func (e *EnhancedClassifier) ReloadAllRules() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// This would typically reload from configuration files
	// For now, just return success
	e.updateMetrics("rules_reloaded", 1)
	return nil
}

// GetClassificationMetrics implements EnhancedClassifierInterface
func (e *EnhancedClassifier) GetClassificationMetrics() map[string]interface{} {
	e.metricsLock.RLock()
	defer e.metricsLock.RUnlock()

	result := make(map[string]interface{})
	for k, v := range e.metrics {
		result[k] = v
	}
	return result
}

// SetThresholds implements EnhancedClassifierInterface
func (e *EnhancedClassifier) SetThresholds(thresholds map[string]float64) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for key, value := range thresholds {
		e.thresholds[key] = value
	}

	e.updateMetrics("thresholds_updated", 1)
	return nil
}

// Custom Framework Classifier methods
func (c *CustomFrameworkClassifier) ClassifyEvent(event *pb.SecurityEvent) []common.Classification {
	if !c.enabled {
		return []common.Classification{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	var classifications []common.Classification

	for _, rule := range c.rules {
		if c.matchesRule(rule, event) {
			classifications = append(classifications, common.Classification{
				Framework:  rule.Framework,
				Category:   rule.Category,
				Confidence: rule.Confidence,
				Metadata:   rule.Metadata,
			})
		}
	}

	return classifications
}

func (c *CustomFrameworkClassifier) matchesRule(rule common.CustomFrameworkRule, event *pb.SecurityEvent) bool {
	// Simple pattern matching for demonstration
	for _, pattern := range rule.Patterns {
		if event.Command != "" && event.Command == pattern {
			return true
		}
		if event.FilePath != "" && event.FilePath == pattern {
			return true
		}
	}

	// Check conditions if specified
	if len(rule.Conditions) > 0 {
		return c.matchesConditions(rule.Conditions, event)
	}

	return false
}

func (c *CustomFrameworkClassifier) matchesConditions(conditions []common.MatchCondition, event *pb.SecurityEvent) bool {
	for _, condition := range conditions {
		var fieldValue string

		switch condition.Field {
		case "command":
			fieldValue = event.Command
		case "file_path":
			fieldValue = event.FilePath
		case "uid":
			fieldValue = fmt.Sprintf("%d", event.Uid)
		default:
			continue
		}

		switch condition.Operator {
		case "equals":
			if fieldValue != condition.Value {
				return false
			}
		case "contains":
			if fieldValue != condition.Value {
				return false
			}
		}
	}
	return true
}

// Threat Intelligence Classifier methods
func (t *ThreatIntelClassifier) ClassifyEvent(event *pb.SecurityEvent) *common.ThreatIntel {
	if !t.enabled {
		return nil
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	// Simple threat intel matching for demonstration
	for _, mapping := range t.mappings {
		if t.matchesMapping(mapping, event) {
			threatIntel := &common.ThreatIntel{}

			if mapping.ThreatActor != "" {
				threatIntel.ThreatActors = []string{mapping.ThreatActor}
			}
			if mapping.Campaign != "" {
				threatIntel.Campaigns = []string{mapping.Campaign}
			}
			if mapping.Malware != "" {
				threatIntel.Malware = []string{mapping.Malware}
			}
			if len(mapping.IOCs) > 0 {
				threatIntel.IOCs = mapping.IOCs
			}

			return threatIntel
		}
	}

	return nil
}

func (t *ThreatIntelClassifier) matchesMapping(mapping common.ThreatIntelMapping, event *pb.SecurityEvent) bool {
	// Simple pattern matching for demonstration
	eventType := pb.EventType_name[int32(event.EventType)]

	for _, eventMatch := range mapping.EventMatches {
		if eventMatch.EventType == eventType {
			return true
		}
	}

	return false
}
