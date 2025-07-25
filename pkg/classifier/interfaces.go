package classifier

import (
	"fmt"
	pb "pod-controller/pkg/telemetry"
	"time"
)

// EventClassifierInterface defines the interface for event classification
type EventClassifierInterface interface {
	ClassifyEvent(event *pb.SecurityEvent) (common.Severity, string)
}

// Note: ThreatDetectorInterface is already defined in classifier.go

// ExtendedClassifierInterface provides additional functionality for advanced classifiers
type ExtendedClassifierInterface interface {
	EventClassifierInterface

	// Rule management
	ReloadRules() error
	GetRulesInfo() map[string]interface{}

	// Event validation and enrichment
	ValidateEvent(event *pb.SecurityEvent) error
	EnrichEventContext(event *pb.SecurityEvent)

	// Configuration queries
	IsEventTypeEnabled(eventType pb.EventType) bool
	IsTrustedProcess(command string) bool
	IsSuspiciousCommand(command string) bool
	IsSensitivePath(path string) bool
	IsExternalIP(ip string) bool
}

// EnhancedClassifierInterface provides complete classification results
type EnhancedClassifierInterface interface {
	ClassifyEventEnhanced(event *pb.SecurityEvent) (*common.ClassificationResult, error)
	ReloadAllRules() error
	GetClassificationMetrics() map[string]interface{}
	SetThresholds(thresholds map[string]float64) error
}

// ClassifierType represents the type of classifier to use
type ClassifierType string

const (

	ClassifierTypeDefault ClassifierType = "default"
	ClassifierTypeYAML    ClassifierType = "yaml"
	ClassifierTypeCVE     ClassifierType = "cve"
)

// ClassifierConfig holds configuration for classifier creation
type ClassifierConfig struct {
	Type            ClassifierType
	RulesPath       string
	ThreatDetector  ThreatDetectorInterface
	FallbackEnabled bool
	// CVE-specific configuration
	CVEDataPath       string
	CVEAPIKey         string
	CVEAPIEndpoint    string
	CVEUpdateInterval time.Duration
}

// NewClassifier creates a classifier based on the configuration
func NewClassifier(config *ClassifierConfig) (EventClassifierInterface, error) {
	switch config.Type {
	case ClassifierTypeDefault:
		return NewEventClassifier(config.ThreatDetector), nil

	case ClassifierTypeYAML:
		// TODO: Implement YAML classifier integration
		// For now, fall back to default to avoid import cycles
		return NewEventClassifier(config.ThreatDetector), nil

	case ClassifierTypeCVE:
		// TODO: Implement CVE classifier in Phase 2
		// For now, fall back to default
		return NewEventClassifier(config.ThreatDetector), nil

	default:
		if config.FallbackEnabled {
			return NewEventClassifier(config.ThreatDetector), nil
		}
		return nil, fmt.Errorf("unknown classifier type: %s", config.Type)
	}
}
