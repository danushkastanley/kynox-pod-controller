package server

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"pod-controller/pkg/classifier"
	"pod-controller/pkg/common"
	"pod-controller/pkg/rules"
	pb "pod-controller/pkg/telemetry"

	"github.com/sirupsen/logrus"
)

// ClassifierConfig holds configuration for the security classifier
type ClassifierConfig struct {
	RulesPath       string
	EnableHotReload bool
	ValidateRules   bool
	MetricsEnabled  bool
}

// CreateAdvancedClassifier creates a sophisticated YAML-based classifier
func CreateAdvancedClassifier(config *ClassifierConfig, threatDetector *ThreatDetector) (classifier.EventClassifierInterface, error) {
	// Validate configuration
	if err := validateClassifierConfig(config); err != nil {
		return nil, fmt.Errorf("invalid classifier configuration: %w", err)
	}

	// Ensure rules file exists and is readable
	if err := validateRulesFile(config.RulesPath); err != nil {
		return nil, fmt.Errorf("rules file validation failed: %w", err)
	}

	// Create YAML-based classifier
	yamlClassifier, err := rules.NewYAMLBasedClassifier(config.RulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize YAML classifier: %w", err)
	}

	// Create enhanced adapter with advanced features
	adapter := &EnhancedYAMLClassifier{
		yamlClassifier: yamlClassifier,
		threatDetector: threatDetector,
		config:         config,
		metrics:        newClassifierMetrics(),
	}

	// Validate rules after loading
	if config.ValidateRules {
		if err := adapter.validateLoadedRules(); err != nil {
			return nil, fmt.Errorf("rule validation failed: %w", err)
		}
	}

	logrus.WithFields(logrus.Fields{
		"rules_path": config.RulesPath,
		"hot_reload": config.EnableHotReload,
		"metrics":    config.MetricsEnabled,
		"validation": config.ValidateRules,
	}).Info("Advanced YAML classifier initialized successfully")

	return adapter, nil
}

// EnhancedYAMLClassifier provides enterprise-grade YAML-based classification
type EnhancedYAMLClassifier struct {
	yamlClassifier *rules.YAMLBasedClassifier
	threatDetector *ThreatDetector
	config         *ClassifierConfig
	metrics        *ClassifierMetrics
}

// Ensure it implements the interface
var _ classifier.EventClassifierInterface = (*EnhancedYAMLClassifier)(nil)

// ClassifyEvent implements sophisticated event classification with metrics and validation
func (e *EnhancedYAMLClassifier) ClassifyEvent(event *pb.SecurityEvent) (common.Severity, string) {
	startTime := time.Now()

	// Pre-classification validation
	if err := e.yamlClassifier.ValidateEvent(event); err != nil {
		e.metrics.recordValidationError()
		logrus.WithError(err).WithField("event_type", event.EventType).Warn("Event validation failed")
		return common.SeverityLow, fmt.Sprintf("Invalid event: %v", err)
	}

	// Check if event type is enabled
	if !e.yamlClassifier.IsEventTypeEnabled(event.EventType) {
		e.metrics.recordSkippedEvent(event.EventType)
		return common.SeverityLow, "Event type disabled by rules"
	}

	// Enrich event context before classification
	e.yamlClassifier.EnrichEventContext(event)

	// Perform classification
	severity, message := e.yamlClassifier.ClassifyEvent(event)

	// Record metrics
	if e.config.MetricsEnabled {
		duration := time.Since(startTime)
		e.metrics.recordClassification(event.EventType, severity, duration)
	}

	// Enhanced logging with context
	logrus.WithFields(logrus.Fields{
		"classifier":     "yaml",
		"event_type":     pb.EventType_name[int32(event.EventType)],
		"severity":       severity,
		"command":        event.Command,
		"container_id":   getContainerID(event),
		"classification": message,
	}).Debug("Event classified successfully")

	return severity, message
}

// Advanced interface methods

// ReloadRules provides hot-reload capability with validation
func (e *EnhancedYAMLClassifier) ReloadRules() error {
	logrus.Info("Initiating rule reload...")

	if err := e.yamlClassifier.ReloadRules(); err != nil {
		e.metrics.recordReloadError()
		return fmt.Errorf("rule reload failed: %w", err)
	}

	// Validate rules after reload
	if e.config.ValidateRules {
		if err := e.validateLoadedRules(); err != nil {
			e.metrics.recordValidationError()
			return fmt.Errorf("rule validation failed after reload: %w", err)
		}
	}

	e.metrics.recordSuccessfulReload()
	logrus.Info("Rules reloaded and validated successfully")
	return nil
}

// GetRulesInfo returns comprehensive rule information
func (e *EnhancedYAMLClassifier) GetRulesInfo() map[string]interface{} {
	info := e.yamlClassifier.GetRulesInfo()

	// Add enhanced metadata
	info["classifier_type"] = "enhanced_yaml"
	info["hot_reload_enabled"] = e.config.EnableHotReload
	info["metrics_enabled"] = e.config.MetricsEnabled
	info["validation_enabled"] = e.config.ValidateRules

	if e.config.MetricsEnabled {
		info["metrics"] = e.metrics.getMetrics()
	}

	return info
}

// GetMetrics returns classification metrics
func (e *EnhancedYAMLClassifier) GetMetrics() map[string]interface{} {
	if !e.config.MetricsEnabled {
		return map[string]interface{}{"metrics_disabled": true}
	}
	return e.metrics.getMetrics()
}

// IsEventTypeEnabled checks if an event type should be processed
func (e *EnhancedYAMLClassifier) IsEventTypeEnabled(eventType pb.EventType) bool {
	return e.yamlClassifier.IsEventTypeEnabled(eventType)
}

// IsTrustedProcess checks if a process is trusted
func (e *EnhancedYAMLClassifier) IsTrustedProcess(command string) bool {
	return e.yamlClassifier.IsTrustedProcess(command)
}

// ValidateRules performs comprehensive rule validation
func (e *EnhancedYAMLClassifier) ValidateRules() error {
	return e.validateLoadedRules()
}

// Helper functions

func validateClassifierConfig(config *ClassifierConfig) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}
	if config.RulesPath == "" {
		return fmt.Errorf("rules path cannot be empty")
	}
	return nil
}

func validateRulesFile(rulesPath string) error {
	// Check if file exists
	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		return fmt.Errorf("rules file does not exist: %s", rulesPath)
	}

	// Check if file is readable
	file, err := os.Open(rulesPath)
	if err != nil {
		return fmt.Errorf("cannot read rules file: %w", err)
	}
	defer file.Close()

	// Check file extension
	if ext := filepath.Ext(rulesPath); ext != ".yaml" && ext != ".yml" {
		return fmt.Errorf("rules file must be YAML format, got: %s", ext)
	}

	return nil
}

func (e *EnhancedYAMLClassifier) validateLoadedRules() error {
	rulesInfo := e.yamlClassifier.GetRulesInfo()

	// Check if rules are loaded
	if rulesInfo == nil {
		return fmt.Errorf("no rules loaded")
	}

	// Validate rule structure
	if _, ok := rulesInfo["error"]; ok {
		return fmt.Errorf("rules contain errors: %v", rulesInfo["error"])
	}

	// Additional validation can be added here
	logrus.Debug("Rule validation completed successfully")
	return nil
}

func getContainerID(event *pb.SecurityEvent) string {
	if ctx := event.GetContainerContext(); ctx != nil {
		return ctx["container_id"]
	}
	return "unknown"
}
