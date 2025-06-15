package rules

import (
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v2"

	"pod-controller/pkg/classifier"
	pb "pod-controller/pkg/telemetry"

	"github.com/sirupsen/logrus"
)

// RuleEngine manages and evaluates security rules
type RuleEngine struct {
	rules     *SecurityRules
	mu        sync.RWMutex
	rulesPath string
	patterns  map[string]*regexp.Regexp // Compiled regex patterns for performance
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(rulesPath string) (*RuleEngine, error) {
	engine := &RuleEngine{
		rulesPath: rulesPath,
		patterns:  make(map[string]*regexp.Regexp),
	}

	if err := engine.LoadRules(); err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	return engine, nil
}

// LoadRules loads rules from the YAML file
func (re *RuleEngine) LoadRules() error {
	re.mu.Lock()
	defer re.mu.Unlock()

	data, err := ioutil.ReadFile(re.rulesPath)
	if err != nil {
		return fmt.Errorf("failed to read rules file %s: %w", re.rulesPath, err)
	}

	var rules SecurityRules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	// Validate rules
	if err := re.validateRules(&rules); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	// Compile regex patterns
	if err := re.compilePatterns(&rules); err != nil {
		return fmt.Errorf("failed to compile patterns: %w", err)
	}

	re.rules = &rules
	logrus.Infof("Loaded security rules from %s (version: %s)", re.rulesPath, rules.Metadata.Version)

	return nil
}

// validateRules performs basic validation on loaded rules
func (re *RuleEngine) validateRules(rules *SecurityRules) error {
	if rules.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}

	if rules.Kind != "SecurityRules" {
		return fmt.Errorf("kind must be 'SecurityRules', got '%s'", rules.Kind)
	}

	// Validate severity levels
	validSeverities := map[string]bool{
		"LOW": true, "WARN": true, "HIGH": true, "CRITICAL": true,
	}

	if !validSeverities[rules.Global.DefaultSeverity] {
		return fmt.Errorf("invalid default severity: %s", rules.Global.DefaultSeverity)
	}

	return nil
}

// compilePatterns pre-compiles regex patterns for better performance
func (re *RuleEngine) compilePatterns(rules *SecurityRules) error {
	// Clear existing patterns
	re.patterns = make(map[string]*regexp.Regexp)

	// Compile command patterns
	for _, rule := range rules.Commands.Suspicious {
		for _, pattern := range rule.Patterns {
			if _, err := regexp.Compile(pattern); err != nil {
				logrus.Warnf("Invalid regex pattern '%s': %v", pattern, err)
			}
		}
	}

	for _, rule := range rules.Commands.Trusted {
		for _, pattern := range rule.Patterns {
			if _, err := regexp.Compile(pattern); err != nil {
				logrus.Warnf("Invalid regex pattern '%s': %v", pattern, err)
			}
		}
	}

	return nil
}

// EvaluateEvent evaluates a security event against the loaded rules
func (re *RuleEngine) EvaluateEvent(event *pb.SecurityEvent) (classifier.Severity, string) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	if re.rules == nil {
		return classifier.SeverityLow, "No rules loaded"
	}

	// Create evaluation context
	ctx := re.createEvaluationContext(event)

	// Check if event type is enabled
	eventTypeName := pb.EventType_name[int32(event.EventType)]
	if eventConfig, exists := re.rules.EventTypes[eventTypeName]; exists {
		if !eventConfig.Enabled {
			return classifier.SeverityLow, "Event type disabled"
		}
	}

	// Evaluate based on event type
	switch event.EventType {
	case pb.EventType_EXEC:
		return re.evaluateExecEvent(event, ctx)
	case pb.EventType_OPEN:
		return re.evaluateFileEvent(event, ctx)
	case pb.EventType_CONNECT, pb.EventType_BIND:
		return re.evaluateNetworkEvent(event, ctx)
	case pb.EventType_CHMOD:
		return re.evaluateChmodEvent(event, ctx)
	case pb.EventType_SETUID, pb.EventType_SETGID:
		return re.evaluatePrivilegeEvent(event, ctx)
	case pb.EventType_PTRACE:
		return re.evaluatePtraceEvent(event, ctx)
	case pb.EventType_MOUNT, pb.EventType_UMOUNT:
		return re.evaluateMountEvent(event, ctx)
	case pb.EventType_CAPSET:
		return re.evaluateCapsetEvent(event, ctx)
	case pb.EventType_BPF_PROG, pb.EventType_SECCOMP:
		return re.evaluateSecurityEvent(event, ctx)
	default:
		return re.getDefaultSeverity(eventTypeName), "Unknown event type"
	}
}

// createEvaluationContext creates context for rule evaluation
func (re *RuleEngine) createEvaluationContext(event *pb.SecurityEvent) *RuleEvaluationContext {
	ctx := &RuleEvaluationContext{
		Command:         event.Command,
		FilePath:        event.FilePath,
		UID:             event.Uid,
		GID:             event.Gid,
		PID:             event.Pid,
		IsRoot:          event.Uid == 0,
		DestinationIP:   event.DestinationIp,
		DestinationPort: event.DestinationPort,
	}

	// Extract container context
	if containerCtx := event.GetContainerContext(); containerCtx != nil {
		ctx.ContainerID = containerCtx["container_id"]
		ctx.Namespace = containerCtx["namespace"]
		ctx.PodName = containerCtx["pod_name"]
		ctx.IsContainer = ctx.ContainerID != ""
	}

	// Check if connecting to external network
	if event.DestinationIp != "" {
		ctx.ExternalNetwork = re.isExternalIP(event.DestinationIp)
	}

	return ctx
}

// evaluateExecEvent evaluates process execution events
func (re *RuleEngine) evaluateExecEvent(event *pb.SecurityEvent, ctx *RuleEvaluationContext) (classifier.Severity, string) {
	command := strings.ToLower(strings.TrimSpace(event.Command))

	// Check if process is trusted first
	if re.isTrustedProcess(command) {
		return classifier.SeverityLow, "Trusted process execution"
	}

	// Check suspicious commands
	for _, rule := range re.rules.Commands.Suspicious {
		if severity, message, matched := re.evaluateCommandRule(rule, command, ctx); matched {
			return severity, message
		}
	}

	// Default severity for exec events
	return re.getDefaultSeverity("EXEC"), "Process execution"
}

// evaluateFileEvent evaluates file access events
func (re *RuleEngine) evaluateFileEvent(event *pb.SecurityEvent, ctx *RuleEvaluationContext) (classifier.Severity, string) {
	filePath := event.FilePath

	// Check trusted processes accessing common monitoring paths
	if (strings.HasPrefix(filePath, "/proc/") || strings.HasPrefix(filePath, "/sys/")) &&
		re.isTrustedProcess(ctx.Command) {
		return classifier.SeverityLow, "Legitimate system monitoring"
	}

	// Check sensitive files
	for _, rule := range re.rules.Filesystem.SensitiveFiles {
		if severity, message, matched := re.evaluateFileRule(rule, filePath, ctx); matched {
			return severity, message
		}
	}

	// Check sensitive directories
	for _, rule := range re.rules.Filesystem.SensitiveDirectories {
		if severity, message, matched := re.evaluateFileRule(rule, filePath, ctx); matched {
			return severity, message
		}
	}

	return re.getDefaultSeverity("OPEN"), "File access"
}

// evaluateNetworkEvent evaluates network connection events
func (re *RuleEngine) evaluateNetworkEvent(event *pb.SecurityEvent, ctx *RuleEvaluationContext) (classifier.Severity, string) {
	// Check for external connections
	if ctx.ExternalNetwork {
		if ctx.IsRoot && !re.isTrustedProcess(ctx.Command) {
			return classifier.SeverityCritical, "Root process connecting to external IP"
		}
		if re.isSuspiciousCommand(ctx.Command) {
			return classifier.SeverityHigh, "Suspicious command connecting to external IP"
		}
		return classifier.SeverityWarn, "External network connection detected"
	}

	// Check suspicious ports
	for _, rule := range re.rules.Network.SuspiciousPorts {
		if re.containsPort(rule.Ports, int(ctx.DestinationPort)) {
			severity := re.evaluateNetworkConditions(rule.Conditions, ctx, ParseSeverity(rule.Severity))
			return severity.ToClassifierSeverity(), fmt.Sprintf("Connection to suspicious port %d (%s)", ctx.DestinationPort, rule.Name)
		}
	}

	// Check for suspicious commands doing network activity
	if re.isSuspiciousCommand(ctx.Command) {
		if ctx.IsRoot {
			return classifier.SeverityCritical, "Suspicious network activity from root process"
		}
		return classifier.SeverityHigh, "Suspicious network activity detected"
	}

	return re.getDefaultSeverity("CONNECT"), "Network connection"
}

// evaluateChmodEvent evaluates file permission change events
func (re *RuleEngine) evaluateChmodEvent(event *pb.SecurityEvent, ctx *RuleEvaluationContext) (classifier.Severity, string) {
	mode := event.Mode
	filePath := event.FilePath

	// Check if target is a sensitive file/directory
	if re.isSensitivePath(filePath) {
		if !re.isTrustedProcess(ctx.Command) {
			return classifier.SeverityCritical, "Permission change on sensitive file"
		}
		return classifier.SeverityWarn, "Legitimate permission change"
	}

	// Check for world-writable permissions
	worldWritable := mode&0002 != 0
	if worldWritable {
		perms := mode & 0777
		if perms == 0777 || strings.HasPrefix(filePath, "/etc/") ||
			strings.HasPrefix(filePath, "/usr/") || strings.HasPrefix(filePath, "/bin/") {
			if ctx.IsRoot && !re.isTrustedProcess(ctx.Command) {
				return classifier.SeverityCritical, "Dangerous permission change detected"
			}
			return classifier.SeverityHigh, "World-writable permission set"
		}
	}

	return re.getDefaultSeverity("CHMOD"), "File permission modification"
}

// evaluatePrivilegeEvent evaluates privilege escalation events
func (re *RuleEngine) evaluatePrivilegeEvent(event *pb.SecurityEvent, ctx *RuleEvaluationContext) (classifier.Severity, string) {
	if !re.isTrustedProcess(ctx.Command) {
		return classifier.SeverityCritical, "Privilege escalation detected"
	}
	return classifier.SeverityLow, "Legitimate privilege operation"
}

// evaluatePtraceEvent evaluates ptrace events
func (re *RuleEngine) evaluatePtraceEvent(event *pb.SecurityEvent, ctx *RuleEvaluationContext) (classifier.Severity, string) {
	if !re.isTrustedProcess(ctx.Command) {
		if ctx.IsRoot {
			return classifier.SeverityCritical, "Root process debugging attempt detected"
		}
		return classifier.SeverityHigh, "Process debugging attempt detected"
	}
	return classifier.SeverityLow, "Legitimate debug operation"
}

// evaluateMountEvent evaluates mount/umount events
func (re *RuleEngine) evaluateMountEvent(event *pb.SecurityEvent, ctx *RuleEvaluationContext) (classifier.Severity, string) {
	if re.isSensitivePath(ctx.FilePath) {
		if !re.isTrustedProcess(ctx.Command) {
			return classifier.SeverityCritical, "Sensitive filesystem mount detected"
		}
		return classifier.SeverityLow, "Legitimate mount operation"
	}
	return classifier.SeverityWarn, "Filesystem mount operation"
}

// evaluateCapsetEvent evaluates capability set events
func (re *RuleEngine) evaluateCapsetEvent(event *pb.SecurityEvent, ctx *RuleEvaluationContext) (classifier.Severity, string) {
	if !re.isTrustedProcess(ctx.Command) {
		return classifier.SeverityCritical, "Capability modification detected"
	}
	return classifier.SeverityLow, "Legitimate capability operation"
}

// evaluateSecurityEvent evaluates eBPF and seccomp events
func (re *RuleEngine) evaluateSecurityEvent(event *pb.SecurityEvent, ctx *RuleEvaluationContext) (classifier.Severity, string) {
	if !re.isTrustedProcess(ctx.Command) {
		return classifier.SeverityCritical, "Security mechanism modification detected"
	}
	return classifier.SeverityLow, "Legitimate security operation"
}

// Helper methods

// evaluateCommandRule evaluates a command rule against a command
func (re *RuleEngine) evaluateCommandRule(rule CommandRule, command string, ctx *RuleEvaluationContext) (classifier.Severity, string, bool) {
	// Check if command matches any pattern
	matched := false
	for _, pattern := range rule.Patterns {
		if strings.Contains(command, strings.ToLower(pattern)) {
			matched = true
			break
		}
	}

	if !matched {
		return classifier.SeverityLow, "", false
	}

	// Apply base severity
	baseSeverity := ParseSeverity(rule.Severity)

	// Check conditions for severity escalation
	for _, condition := range rule.Conditions {
		if re.matchesCondition(condition, ctx) {
			if condition.Severity != "" {
				return ParseSeverity(condition.Severity).ToClassifierSeverity(),
					fmt.Sprintf("%s command execution (%s)", rule.Name, condition.Severity), true
			}
			if condition.EscalateSeverity != "" {
				return ParseSeverity(condition.EscalateSeverity).ToClassifierSeverity(),
					fmt.Sprintf("%s command execution (escalated)", rule.Name), true
			}
		}
	}

	return baseSeverity.ToClassifierSeverity(), fmt.Sprintf("%s command execution", rule.Name), true
}

// evaluateFileRule evaluates a file rule against a file path
func (re *RuleEngine) evaluateFileRule(rule FileRule, filePath string, ctx *RuleEvaluationContext) (classifier.Severity, string, bool) {
	// Check if file path matches any pattern
	matched := false
	for _, path := range rule.Paths {
		if re.matchesPath(path, filePath) {
			matched = true
			break
		}
	}

	if !matched {
		return classifier.SeverityLow, "", false
	}

	// Apply base severity
	baseSeverity := ParseSeverity(rule.Severity)

	// Check conditions for severity escalation
	for _, condition := range rule.Conditions {
		if re.matchesFileCondition(condition, ctx) {
			if condition.Severity != "" {
				return ParseSeverity(condition.Severity).ToClassifierSeverity(),
					fmt.Sprintf("%s file access (%s)", rule.Name, condition.Severity), true
			}
		}
	}

	return baseSeverity.ToClassifierSeverity(), fmt.Sprintf("%s file access", rule.Name), true
}

// evaluateNetworkConditions evaluates network conditions
func (re *RuleEngine) evaluateNetworkConditions(conditions []NetworkCondition, ctx *RuleEvaluationContext, baseSeverity SeverityLevel) SeverityLevel {
	for _, condition := range conditions {
		if re.matchesNetworkCondition(condition, ctx) {
			if condition.Severity != "" {
				return ParseSeverity(condition.Severity)
			}
			if condition.EscalateSeverity != "" {
				return ParseSeverity(condition.EscalateSeverity)
			}
		}
	}
	return baseSeverity
}

// matchesCondition checks if a command condition matches the context
func (re *RuleEngine) matchesCondition(condition CommandCondition, ctx *RuleEvaluationContext) bool {
	if condition.UIDIsRoot && !ctx.IsRoot {
		return false
	}
	if condition.ExternalNetwork && !ctx.ExternalNetwork {
		return false
	}
	if condition.InContainer && !ctx.IsContainer {
		return false
	}
	if condition.TargetIsSensitive && !re.isSensitivePath(ctx.FilePath) {
		return false
	}
	return true
}

// matchesFileCondition checks if a file condition matches the context
func (re *RuleEngine) matchesFileCondition(condition FileCondition, ctx *RuleEvaluationContext) bool {
	if condition.UIDIsRoot && !ctx.IsRoot {
		return false
	}
	if condition.WriteAccess && !ctx.WriteAccess {
		return false
	}
	return true
}

// matchesNetworkCondition checks if a network condition matches the context
func (re *RuleEngine) matchesNetworkCondition(condition NetworkCondition, ctx *RuleEvaluationContext) bool {
	if condition.ExternalDestination && !ctx.ExternalNetwork {
		return false
	}
	if condition.UnauthorizedProcess && re.isTrustedProcess(ctx.Command) {
		return false
	}
	return true
}

// matchesPath checks if a file path matches a pattern (supports wildcards)
func (re *RuleEngine) matchesPath(pattern, path string) bool {
	// Simple wildcard matching
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, path)
		return matched
	}
	return strings.HasPrefix(path, pattern)
}

// isTrustedProcess checks if a command is from a trusted process
func (re *RuleEngine) isTrustedProcess(command string) bool {
	command = strings.ToLower(strings.TrimSpace(command))

	for _, rule := range re.rules.Commands.Trusted {
		for _, pattern := range rule.Patterns {
			if strings.Contains(command, strings.ToLower(pattern)) {
				return true
			}
		}
	}
	return false
}

// isSuspiciousCommand checks if a command is suspicious
func (re *RuleEngine) isSuspiciousCommand(command string) bool {
	command = strings.ToLower(strings.TrimSpace(command))

	for _, rule := range re.rules.Commands.Suspicious {
		for _, pattern := range rule.Patterns {
			if strings.Contains(command, strings.ToLower(pattern)) {
				return true
			}
		}
	}
	return false
}

// isSensitivePath checks if a path is sensitive
func (re *RuleEngine) isSensitivePath(path string) bool {
	// Check sensitive files
	for _, rule := range re.rules.Filesystem.SensitiveFiles {
		for _, rulePath := range rule.Paths {
			if re.matchesPath(rulePath, path) {
				return true
			}
		}
	}

	// Check sensitive directories
	for _, rule := range re.rules.Filesystem.SensitiveDirectories {
		for _, rulePath := range rule.Paths {
			if re.matchesPath(rulePath, path) {
				return true
			}
		}
	}

	return false
}

// isExternalIP checks if an IP is external (not in private networks)
func (re *RuleEngine) isExternalIP(ip string) bool {
	if ip == "" {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check against configured private networks
	for _, network := range re.rules.Network.PrivateNetworks {
		_, ipnet, err := net.ParseCIDR(network)
		if err != nil {
			continue
		}
		if ipnet.Contains(parsedIP) {
			return false
		}
	}

	return true
}

// containsPort checks if a port is in the list
func (re *RuleEngine) containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// getDefaultSeverity gets the default severity for an event type
func (re *RuleEngine) getDefaultSeverity(eventType string) classifier.Severity {
	if config, exists := re.rules.EventTypes[eventType]; exists {
		return ParseSeverity(config.DefaultSeverity).ToClassifierSeverity()
	}
	return ParseSeverity(re.rules.Global.DefaultSeverity).ToClassifierSeverity()
}

// GetRulesInfo returns information about the loaded rules
func (re *RuleEngine) GetRulesInfo() map[string]interface{} {
	re.mu.RLock()
	defer re.mu.RUnlock()

	if re.rules == nil {
		return map[string]interface{}{"error": "No rules loaded"}
	}

	return map[string]interface{}{
		"metadata":            re.rules.Metadata,
		"global_config":       re.rules.Global,
		"event_types_count":   len(re.rules.EventTypes),
		"suspicious_commands": len(re.rules.Commands.Suspicious),
		"trusted_commands":    len(re.rules.Commands.Trusted),
		"sensitive_files":     len(re.rules.Filesystem.SensitiveFiles),
		"sensitive_dirs":      len(re.rules.Filesystem.SensitiveDirectories),
		"network_rules":       len(re.rules.Network.SuspiciousPorts),
	}
}

// ReloadRules reloads the rules from file
func (re *RuleEngine) ReloadRules() error {
	logrus.Info("Reloading security rules...")
	if err := re.LoadRules(); err != nil {
		logrus.WithError(err).Error("Failed to reload rules")
		return err
	}
	logrus.Info("Security rules reloaded successfully")
	return nil
}
