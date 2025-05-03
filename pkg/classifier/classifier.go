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

// EventClassifier determines the severity of security events
type EventClassifier struct {
	// Configurable rules
	suspiciousCommands    map[string]bool
	sensitivePaths       map[string]bool
	suspiciousNetworkPorts map[int32]bool
}

// NewEventClassifier creates a new event classifier with default rules
func NewEventClassifier() *EventClassifier {
	return &EventClassifier{
		suspiciousCommands: map[string]bool{
			"nc":        true,
			"netcat":    true,
			"ncat":      true,
			"wget":      true,
			"curl":      true,
			"bash":      true,
			"sh":        true,
			"python":    true,
			"perl":      true,
			"nmap":      true,
			"tcpdump":   true,
			"wireshark": true,
		},
		sensitivePaths: map[string]bool{
			"/etc/shadow":           true,
			"/etc/passwd":           true,
			"/etc/sudoers":         true,
			"/etc/kubernetes":       true,
			"/var/run/docker.sock": true,
			"/proc":                true,
			"/sys":                 true,
			"/.ssh":               true,
		},
		suspiciousNetworkPorts: map[int32]bool{
			22:    true, // SSH
			3389:  true, // RDP
			4444:  true, // Common backdoor
			6379:  true, // Redis
			27017: true, // MongoDB
			3306:  true, // MySQL
			5432:  true, // PostgreSQL
		},
	}
}

// ClassifyEvent determines the severity of a security event
func (c *EventClassifier) ClassifyEvent(event *pb.SecurityEvent) (Severity, string) {
	// Extract common fields
	isRoot := event.GetUid() == 0
	command := event.GetCommand()
	
	// Check for root-level activities first
	if isRoot {
		switch event.GetEventType() {
		case pb.EventType_SETUID:
			return SeverityCritical, "Root privilege escalation detected"
			
		case pb.EventType_BPF_PROG:
			return SeverityCritical, "Root BPF program loading detected"
			
		case pb.EventType_PTRACE:
			return SeverityCritical, "Root process debugging attempt detected"
		}
	}

	// Classify based on event type
	switch event.GetEventType() {
	case pb.EventType_EXEC:
		if c.isSuspiciousCommand(command) {
			if isRoot {
				return SeverityCritical, "Suspicious command execution with root privileges"
			}
			return SeverityHigh, "Suspicious command execution detected"
		}
		return SeverityLow, "Process execution"

	case pb.EventType_MOUNT:
		if c.isSensitivePath(event.GetFilePath()) {
			return SeverityCritical, "Sensitive filesystem mount detected"
		}
		return SeverityWarn, "Filesystem mount operation"

	case pb.EventType_OPEN:
		if c.isSensitivePath(event.GetFilePath()) {
			if isRoot {
				return SeverityHigh, "Sensitive file access with root privileges"
			}
			return SeverityWarn, "Sensitive file access detected"
		}
		return SeverityLow, "File access"

	case pb.EventType_CONNECT, pb.EventType_BIND:
		if c.isSuspiciousPort(event.GetDestinationPort()) {
			if isRoot {
				return SeverityCritical, "Root process accessing sensitive port"
			}
			return SeverityHigh, "Process accessing sensitive port"
		}
		if c.isSuspiciousCommand(command) {
			if isRoot {
				return SeverityCritical, "Suspicious network activity from root process"
			}
			return SeverityHigh, "Suspicious network activity detected"
		}
		return SeverityLow, "Network connection"

	case pb.EventType_CHMOD:
		if event.GetMode()&0777 == 0777 {
			return SeverityHigh, "World-writable permission (777) detected"
		}
		return SeverityWarn, "File permission modification"

	case pb.EventType_SECCOMP:
		if isRoot {
			return SeverityCritical, "Root seccomp filter modification"
		}
		return SeverityHigh, "Seccomp filter modification attempt"

	default:
		return SeverityLow, "Unknown event type"
	}
}

// Helper functions
func (c *EventClassifier) isSuspiciousCommand(command string) bool {
	command = strings.ToLower(strings.TrimSpace(command))
	for suspicious := range c.suspiciousCommands {
		if strings.Contains(command, suspicious) {
			return true
		}
	}
	return false
}

func (c *EventClassifier) isSensitivePath(path string) bool {
	path = strings.TrimSpace(path)
	for sensitive := range c.sensitivePaths {
		if strings.HasPrefix(path, sensitive) {
			return true
		}
	}
	return false
}

func (c *EventClassifier) isSuspiciousPort(port int32) bool {
	return c.suspiciousNetworkPorts[port]
}
