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
	trustedProcesses     map[string]bool
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
		},
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
			"runc:[2:INIT]":        true,
			"containerd":           true,
			"containerd-shim":      true,
			"docker":               true,
			"kubelet":              true,
			"k3s":                  true,
			"k3s-agent":           true,
			"k3s-server":          true,
			"cri-o":               true,
			"cri-containerd":      true,
		},
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
		if c.isSensitivePath(event.GetFilePath()) {
			if isRoot && !c.isTrustedProcess(command) {
				return SeverityHigh, "Sensitive file access with root privileges"
			}
			return SeverityWarn, "Sensitive file access detected"
		}
		return SeverityLow, "File access"

	case pb.EventType_CONNECT, pb.EventType_BIND:
		if c.isSuspiciousPort(event.GetDestinationPort()) {
			if isRoot && !c.isTrustedProcess(command) {
				return SeverityCritical, "Root process accessing sensitive port"
			}
			return SeverityHigh, "Process accessing sensitive port"
		}
		if c.isSuspiciousCommand(command) {
			if isRoot && !c.isTrustedProcess(command) {
				return SeverityCritical, "Suspicious network activity from root process"
			}
			return SeverityHigh, "Suspicious network activity detected"
		}
		return SeverityLow, "Network connection"

	case pb.EventType_CHMOD:
		if c.isSensitivePath(event.GetFilePath()) {
			if isRoot && !c.isTrustedProcess(command) {
				return SeverityCritical, "Critical: Permission modification on sensitive file"
			}
			return SeverityHigh, "Permission modification on sensitive file"
		}
		if event.GetMode()&0777 == 0777 {
			if !c.isTrustedProcess(command) {
				return SeverityHigh, "World-writable permission (777) detected"
			}
			return SeverityWarn, "Legitimate permission change"
		}
		return SeverityWarn, "File permission modification"

	default:
		return SeverityLow, "Unknown event type"
	}
}

func (c *EventClassifier) isSuspiciousCommand(command string) bool {
	for cmd := range c.suspiciousCommands {
		if strings.Contains(command, cmd) {
			return true
		}
	}
	return false
}

func (c *EventClassifier) isSensitivePath(path string) bool {
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

func (c *EventClassifier) isTrustedProcess(command string) bool {
	for trusted := range c.trustedProcesses {
		if strings.Contains(command, trusted) {
			return true
		}
	}
	return false
}
