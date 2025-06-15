package rules

import (
	"fmt"
	"strings"

	"pod-controller/pkg/classifier"
	pb "pod-controller/pkg/telemetry"

	"github.com/sirupsen/logrus"
)

// YAMLBasedClassifier is a classifier that uses YAML-based rules
type YAMLBasedClassifier struct {
	ruleEngine *RuleEngine
}

// NewYAMLBasedClassifier creates a new YAML-based classifier
func NewYAMLBasedClassifier(rulesPath string) (*YAMLBasedClassifier, error) {
	engine, err := NewRuleEngine(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule engine: %w", err)
	}

	return &YAMLBasedClassifier{
		ruleEngine: engine,
	}, nil
}

// ClassifyEvent classifies a security event using YAML rules
func (c *YAMLBasedClassifier) ClassifyEvent(event *pb.SecurityEvent) (classifier.Severity, string) {
	if c.ruleEngine == nil {
		logrus.Warn("Rule engine not initialized, using default classification")
		return classifier.SeverityLow, "Rule engine not available"
	}

	return c.ruleEngine.EvaluateEvent(event)
}

// ReloadRules reloads the classification rules
func (c *YAMLBasedClassifier) ReloadRules() error {
	if c.ruleEngine == nil {
		return fmt.Errorf("rule engine not initialized")
	}

	return c.ruleEngine.ReloadRules()
}

// GetRulesInfo returns information about the loaded rules
func (c *YAMLBasedClassifier) GetRulesInfo() map[string]interface{} {
	if c.ruleEngine == nil {
		return map[string]interface{}{"error": "Rule engine not initialized"}
	}

	return c.ruleEngine.GetRulesInfo()
}

// IsEventTypeEnabled checks if an event type is enabled for monitoring
func (c *YAMLBasedClassifier) IsEventTypeEnabled(eventType pb.EventType) bool {
	if c.ruleEngine == nil {
		return true // Default to enabled if no rules
	}

	c.ruleEngine.mu.RLock()
	defer c.ruleEngine.mu.RUnlock()

	if c.ruleEngine.rules == nil {
		return true
	}

	eventTypeName := pb.EventType_name[int32(eventType)]
	if config, exists := c.ruleEngine.rules.EventTypes[eventTypeName]; exists {
		return config.Enabled
	}

	return true // Default to enabled if not configured
}

// GetGlobalConfig returns the global configuration
func (c *YAMLBasedClassifier) GetGlobalConfig() *GlobalConfig {
	if c.ruleEngine == nil || c.ruleEngine.rules == nil {
		return nil
	}

	c.ruleEngine.mu.RLock()
	defer c.ruleEngine.mu.RUnlock()

	return &c.ruleEngine.rules.Global
}

// IsTrustedProcess checks if a process is trusted based on rules
func (c *YAMLBasedClassifier) IsTrustedProcess(command string) bool {
	if c.ruleEngine == nil || c.ruleEngine.rules == nil {
		return false
	}

	return c.ruleEngine.isTrustedProcess(command)
}

// IsSuspiciousCommand checks if a command is suspicious based on rules
func (c *YAMLBasedClassifier) IsSuspiciousCommand(command string) bool {
	if c.ruleEngine == nil || c.ruleEngine.rules == nil {
		return false
	}

	return c.ruleEngine.isSuspiciousCommand(command)
}

// IsSensitivePath checks if a path is sensitive based on rules
func (c *YAMLBasedClassifier) IsSensitivePath(path string) bool {
	if c.ruleEngine == nil || c.ruleEngine.rules == nil {
		return false
	}

	return c.ruleEngine.isSensitivePath(path)
}

// IsExternalIP checks if an IP is external based on rules
func (c *YAMLBasedClassifier) IsExternalIP(ip string) bool {
	if c.ruleEngine == nil || c.ruleEngine.rules == nil {
		// Default behavior for external IP detection
		return !isPrivateIP(ip)
	}

	return c.ruleEngine.isExternalIP(ip)
}

// GetContainerPolicy returns the container policy for a given container/pod
func (c *YAMLBasedClassifier) GetContainerPolicy(namespace, podName, containerID string) *ContainerPolicy {
	if c.ruleEngine == nil || c.ruleEngine.rules == nil {
		return nil
	}

	c.ruleEngine.mu.RLock()
	defer c.ruleEngine.mu.RUnlock()

	// Check for matching policies
	target := fmt.Sprintf("%s/%s", namespace, podName)

	for _, policy := range c.ruleEngine.rules.Containers.Policies {
		for _, pattern := range policy.Patterns {
			if c.matchesContainerPattern(pattern, target, namespace, podName) {
				return &policy
			}
		}
	}

	// Return default policy
	return &c.ruleEngine.rules.Containers.DefaultPolicy
}

// matchesContainerPattern checks if a container matches a pattern
func (c *YAMLBasedClassifier) matchesContainerPattern(pattern, target, namespace, podName string) bool {
	// Simple pattern matching - can be enhanced with regex
	if strings.Contains(pattern, "*") {
		// Wildcard matching
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			prefix := parts[0]
			suffix := parts[1]
			return strings.HasPrefix(target, prefix) && strings.HasSuffix(target, suffix)
		}
	}

	return target == pattern || namespace == pattern || podName == pattern
}

// GetNotificationRoute returns the notification route for a severity level
func (c *YAMLBasedClassifier) GetNotificationRoute(severity classifier.Severity) *NotificationRoute {
	if c.ruleEngine == nil || c.ruleEngine.rules == nil {
		return nil
	}

	c.ruleEngine.mu.RLock()
	defer c.ruleEngine.mu.RUnlock()

	severityStr := string(severity)
	if route, exists := c.ruleEngine.rules.Notifications.Routing[severityStr]; exists {
		return &route
	}

	return nil
}

// ValidateEvent performs initial validation of an event before classification
func (c *YAMLBasedClassifier) ValidateEvent(event *pb.SecurityEvent) error {
	if event == nil {
		return fmt.Errorf("event is nil")
	}

	if event.Command == "" {
		return fmt.Errorf("event command is empty")
	}

	if event.Pid <= 0 {
		return fmt.Errorf("invalid PID: %d", event.Pid)
	}

	return nil
}

// EnrichEventContext enriches the event with additional context
func (c *YAMLBasedClassifier) EnrichEventContext(event *pb.SecurityEvent) {
	if event == nil {
		return
	}

	// Add classification metadata
	if event.ContainerContext == nil {
		event.ContainerContext = make(map[string]string)
	}

	// Add rule engine metadata
	if c.ruleEngine != nil && c.ruleEngine.rules != nil {
		event.ContainerContext["rule_version"] = c.ruleEngine.rules.Metadata.Version
		event.ContainerContext["rule_name"] = c.ruleEngine.rules.Metadata.Name
	}

	// Add process classification
	if c.IsTrustedProcess(event.Command) {
		event.ContainerContext["process_trust"] = "trusted"
	} else if c.IsSuspiciousCommand(event.Command) {
		event.ContainerContext["process_trust"] = "suspicious"
	} else {
		event.ContainerContext["process_trust"] = "unknown"
	}

	// Add path sensitivity for file events
	if event.FilePath != "" && c.IsSensitivePath(event.FilePath) {
		event.ContainerContext["path_sensitivity"] = "sensitive"
	}

	// Add network classification
	if event.DestinationIp != "" {
		if c.IsExternalIP(event.DestinationIp) {
			event.ContainerContext["network_destination"] = "external"
		} else {
			event.ContainerContext["network_destination"] = "internal"
		}
	}
}

// Helper function for default private IP detection
func isPrivateIP(ip string) bool {
	// This is a fallback implementation
	// The real implementation should use the YAML rules
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.")
}
