package classifier

import (
	"strings"

	pb "pod-controller/pkg/telemetry"
)

// Severity levels for security events
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityWarn     Severity = "WARN"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// ThreatDetectorInterface defines the interface for threat detection
type ThreatDetectorInterface interface {
	IsSuspiciousCommand(cmd string) bool
	IsSuspiciousFileAccess(path string) bool
	IsSuspiciousChmod(path string, mode uint32) bool
	IsExternalConnection(ip string) bool
}

// EventClassifier determines the severity of security events
type EventClassifier struct {
	// Configurable rules
	suspiciousNetworkPorts map[int32]bool
	trustedProcesses       map[string]bool
	// Threat detector for shared logic
	threatDetector ThreatDetectorInterface
}

// Ensure EventClassifier implements the interface
var _ EventClassifierInterface = (*EventClassifier)(nil)

// NewEventClassifier creates a new event classifier with default rules
func NewEventClassifier(threatDetector ThreatDetectorInterface) *EventClassifier {
	return &EventClassifier{
		suspiciousNetworkPorts: map[int32]bool{
			22:    true, // SSH
			23:    true, // Telnet
			3389:  true, // RDP
			6379:  true, // Redis
			27017: true, // MongoDB
			5432:  true, // PostgreSQL
			3306:  true, // MySQL
		},
		trustedProcesses: map[string]bool{
			"runc:[2:INIT]":   true,
			"containerd":      true,
			"containerd-shim": true,
			"docker":          true,
			"kubelet":         true,
			"k3s":             true,
			"k3s-agent":       true,
			"k3s-server":      true,
			"cri-o":           true,
			"cri-containerd":  true,
			// Add monitoring and system processes
			"agent":           true, // Our monitoring agent
			"tokio-runtime":   true, // Rust async runtime
			"systemd":         true, // SystemD processes
			"systemd-oomd":    true,
			"systemd-journal": true,
			"thermald":        true, // Thermal daemon
			"Chrome_IOThread": true, // Browser processes
			"com.docker.back": true, // Docker backend
		},
		threatDetector: threatDetector,
	}
}

// ClassifyEvent determines the severity of a security event
func (c *EventClassifier) ClassifyEvent(event *pb.SecurityEvent) (Severity, string) {
	command := event.GetCommand()
	isRoot := event.GetUid() == 0

	// Skip alerts for trusted system processes
	if c.isTrustedProcess(command) {
		return SeverityLow, "Legitimate system operation"
	}

	// Root-level activities
	if isRoot {
		switch event.GetEventType() {
		case pb.EventType_SETUID:
			// Only alert on non-container-runtime setuid
			if !c.isTrustedProcess(command) {
				return SeverityCritical, "Root privilege escalation detected"
			}
			return SeverityLow, "Legitimate privilege operation"
		case pb.EventType_CAPSET:
			if !c.isTrustedProcess(command) {
				return SeverityCritical, "Root capability modification detected"
			}
			return SeverityLow, "Legitimate capability operation"
		case pb.EventType_PTRACE:
			if !c.isTrustedProcess(command) {
				return SeverityCritical, "Root process debugging attempt detected"
			}
			return SeverityLow, "Legitimate debug operation"
		}
	}

	// Classify based on event type
	switch event.GetEventType() {
	case pb.EventType_EXEC:
		// Special handling for runc - context-sensitive detection
		if strings.Contains(command, "runc") {
			// Check if this is legitimate container runtime usage
			if strings.Contains(command, "runc:[2:INIT]") ||
				strings.Contains(command, "runc:[1:CHILD]") {
				return SeverityLow, "Legitimate container runtime operation"
			}

			// runc executed in potentially suspicious contexts
			if isRoot {
				return SeverityCritical, "Potentially malicious runc execution with root privileges"
			}
			return SeverityHigh, "Suspicious runc execution detected"
		}

		// Handle other suspicious commands
		if c.isSuspiciousCommand(command) {
			if isRoot {
				return SeverityCritical, "Suspicious command execution with root privileges"
			}
			return SeverityHigh, "Suspicious command execution detected"
		}
		return SeverityLow, "Process execution"

	case pb.EventType_MOUNT:
		if c.isSensitivePath(event.GetFilePath()) {
			if !c.isTrustedProcess(command) {
				return SeverityCritical, "Sensitive filesystem mount detected"
			}
			return SeverityLow, "Legitimate mount operation"
		}
		return SeverityWarn, "Filesystem mount operation"

	case pb.EventType_OPEN:
		// Special handling for common monitoring paths
		filePath := event.GetFilePath()

		// Very common monitoring paths that should be LOW severity for trusted processes
		if (strings.HasPrefix(filePath, "/proc/") || strings.HasPrefix(filePath, "/sys/")) && c.isTrustedProcess(command) {
			return SeverityLow, "Legitimate system monitoring"
		}

		if c.isSensitivePath(filePath) {
			if isRoot && !c.isTrustedProcess(command) {
				return SeverityHigh, "Sensitive file access with root privileges"
			}
			return SeverityWarn, "Sensitive file access detected"
		}
		return SeverityLow, "File access"

	case pb.EventType_CONNECT, pb.EventType_BIND:
		// Check for external connections
		if c.threatDetector.IsExternalConnection(event.GetDestinationIp()) {
			if isRoot && !c.isTrustedProcess(command) {
				return SeverityCritical, "Root process connecting to external IP"
			}
			if c.isSuspiciousCommand(command) {
				return SeverityHigh, "Suspicious command connecting to external IP"
			}
			return SeverityWarn, "External network connection detected"
		}

		// Check for suspicious ports
		if c.isSuspiciousPort(event.GetDestinationPort()) {
			if isRoot && !c.isTrustedProcess(command) {
				return SeverityCritical, "Root process accessing sensitive port"
			}
			return SeverityHigh, "Process accessing sensitive port"
		}

		// Check for suspicious commands doing network activity
		if c.isSuspiciousCommand(command) {
			if isRoot && !c.isTrustedProcess(command) {
				return SeverityCritical, "Suspicious network activity from root process"
			}
			return SeverityHigh, "Suspicious network activity detected"
		}
		return SeverityLow, "Network connection"

	case pb.EventType_CHMOD:
		if c.threatDetector.IsSuspiciousChmod(event.GetFilePath(), event.GetMode()) {
			if isRoot && !c.isTrustedProcess(command) {
				return SeverityCritical, "Critical: Suspicious permission modification detected"
			}
			return SeverityHigh, "Suspicious permission modification detected"
		}
		return SeverityWarn, "File permission modification"

	default:
		return SeverityLow, "Unknown event type"
	}
}

func (c *EventClassifier) isSuspiciousCommand(command string) bool {
	return c.threatDetector.IsSuspiciousCommand(command)
}

func (c *EventClassifier) isSensitivePath(path string) bool {
	return c.threatDetector.IsSuspiciousFileAccess(path)
}

func (c *EventClassifier) isSuspiciousPort(port int32) bool {
	return c.suspiciousNetworkPorts[port]
}

func (c *EventClassifier) isTrustedProcess(command string) bool {
	for trusted := range c.trustedProcesses {
		if strings.Contains(command, trusted) {
			return true
		}
	}
	return false
}
