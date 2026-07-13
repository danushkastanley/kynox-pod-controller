package classifier

import (
	"strings"

	"pod-controller/pkg/executable"
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
	IsHighlySuspiciousCommand(cmd string) bool
}

// ShellAnalyzerInterface defines the interface for shell context analysis
type ShellAnalyzerInterface interface {
	IsShell(command string) bool
	AnalyzeExecEvent(event *pb.SecurityEvent) (int, string) // Returns risk level and reason
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
			23:   true, // Telnet (rarely legitimate)
			3389: true, // RDP (Windows)
			// Note: Removed common service ports as they're often legitimate
			// 22 (SSH), 6379 (Redis), 27017 (MongoDB), etc. are commonly used
		},
		trustedProcesses: map[string]bool{
			// Container runtimes
			"runc:[2:INIT]":   true,
			"runc:[1:CHILD]":  true,
			"runc":            true, // Generic runc
			"containerd":      true,
			"containerd-shim": true,
			"docker":          true,
			"dockerd":         true,
			"docker-proxy":    true,
			"cri-o":           true,
			"cri-containerd":  true,
			"crio":            true,
			"conmon":          true, // Container monitor

			// Kubernetes components
			"kubelet":                 true,
			"kube-proxy":              true,
			"kube-apiserver":          true,
			"kube-scheduler":          true,
			"kube-controller-manager": true,
			"etcd":                    true,
			"coredns":                 true,
			"k3s":                     true,
			"k3s-agent":               true,
			"k3s-server":              true,
			"k3s-killall":             true,

			// CNI plugins
			"calico-node":  true,
			"cilium-agent": true,
			"flannel":      true,
			"weave-net":    true,
			"kube-router":  true,
			"aws-cni":      true,

			// Our monitoring agent
			"agent":         true,
			"pod-agent":     true,
			"tokio-runtime": true, // Rust async runtime
			"rasp":          true,

			// System processes
			"systemd":           true,
			"systemd-oomd":      true,
			"systemd-journald":  true,
			"systemd-logind":    true,
			"systemd-networkd":  true,
			"systemd-resolved":  true,
			"systemd-timesyncd": true,
			"systemd-udevd":     true,
			"init":              true,
			"dbus-daemon":       true,
			"dbus":              true,
			"polkitd":           true,
			"thermald":          true,
			"irqbalance":        true,
			"auditd":            true,
			"crond":             true,
			"cron":              true,
			"sshd":              true,
			"rsyslogd":          true,
			"journald":          true,
			"NetworkManager":    true,
			"dhclient":          true,
			"chronyd":           true,
			"ntpd":              true,

			// Common service processes
			"nginx":        true,
			"httpd":        true,
			"apache2":      true,
			"postgres":     true,
			"mysqld":       true,
			"redis-server": true,
			"mongod":       true,

			// Health checks and probes
			"grpc-health-probe": true,
			"health-check":      true,
			"readiness-probe":   true,
			"liveness-probe":    true,
			"curl":              true, // Often used for health checks
			"wget":              true, // Often used for health checks

			// Package managers and common tools
			"apt":     true,
			"apt-get": true,
			"dpkg":    true,
			"yum":     true,
			"rpm":     true,
			"apk":     true,
			"pip":     true,
			"npm":     true,
			"node":    true,
			"python":  true,
			"python3": true,
			"java":    true,
			"go":      true,

			// Shells - these are legitimate in most contexts
			"bash": true,
			"sh":   true,
			"dash": true,
			"ash":  true,
			"zsh":  true,

			// Docker Desktop / development
			"com.docker.back": true,
			"Docker":          true,
			"vpnkit":          true,

			// Browsers (for desktop monitoring)
			"Chrome_IOThread": true,
			"firefox":         true,
			"chrome":          true,
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
		// Check for highly suspicious commands first (crypto miners, exploit tools)
		if c.threatDetector.IsHighlySuspiciousCommand(command) {
			return SeverityCritical, "Highly suspicious/malicious command detected"
		}

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

		// Context-aware shell detection
		// Check the full command path (filePath) for shell-related patterns
		filePath := event.GetFilePath()
		if c.isShellCommand(command) {
			risk, reason := c.analyzeShellContext(event)
			switch risk {
			case 4: // Critical
				return SeverityCritical, reason
			case 3: // High
				return SeverityHigh, reason
			case 2: // Medium
				return SeverityWarn, reason
			default:
				// Low risk shell - check if there are other suspicious signals
				if c.hasDownloadAndExecutePattern(filePath) {
					return SeverityCritical, "Download and execute pattern detected"
				}
				return SeverityLow, reason
			}
		}

		// Handle other suspicious commands (non-shell)
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
		if executable.Matches(command, trusted) {
			return true
		}
	}
	return false
}

// isShellCommand checks if a command is a shell
func (c *EventClassifier) isShellCommand(command string) bool {
	shells := []string{"bash", "sh", "dash", "ash", "zsh", "ksh", "csh", "tcsh", "fish"}
	cmd := strings.ToLower(strings.TrimSpace(command))
	for _, shell := range shells {
		if cmd == shell || strings.HasSuffix(cmd, "/"+shell) {
			return true
		}
	}
	return false
}

// analyzeShellContext performs context-aware shell analysis
// Returns risk level (0-4) and reason
func (c *EventClassifier) analyzeShellContext(event *pb.SecurityEvent) (int, string) {
	command := event.GetCommand()
	filePath := event.GetFilePath() // Full command with arguments
	isRoot := event.GetUid() == 0
	containerCtx := event.GetContainerContext()

	// Check for malicious patterns in arguments (CRITICAL)
	maliciousPatterns := []string{
		"nc -e /bin", // netcat reverse shell
		"ncat -e /bin",
		"bash -i >& /dev/tcp", // bash reverse shell
		"/dev/tcp/",           // bash network redirection
		"/dev/udp/",
		"mkfifo",        // named pipe (often reverse shells)
		"import socket", // python reverse shell
		"import pty",    // python pty spawn
		"fsockopen",     // php reverse shell
		"meterpreter",
		"reverse_tcp",
	}
	for _, pattern := range maliciousPatterns {
		if strings.Contains(strings.ToLower(filePath), pattern) {
			return 4, "Reverse shell pattern detected: " + pattern
		}
	}

	// Check for download-and-execute (HIGH)
	if c.hasDownloadAndExecutePattern(filePath) {
		return 3, "Download and execute pattern"
	}

	// Check for suspicious argument patterns (HIGH)
	suspiciousArgs := []string{
		"base64 -d",
		"base64 --decode",
		"unset HISTFILE",
		"HISTFILE=/dev/null",
		"history -c",
	}
	for _, pattern := range suspiciousArgs {
		if strings.Contains(filePath, pattern) {
			return 3, "Suspicious shell arguments: " + pattern
		}
	}

	// Check parent process - web server spawning shell (HIGH)
	suspiciousParents := []string{
		"nginx", "apache", "httpd", "lighttpd", "caddy",
		"java", "node", "python", "ruby", "php", "php-fpm",
		"gunicorn", "uwsgi", "tomcat", "jetty",
		"postgres", "mysql", "mongod", "redis-server",
	}
	if containerCtx != nil {
		if parentCmd, ok := containerCtx["parent_command"]; ok {
			parentLower := strings.ToLower(parentCmd)
			for _, suspicious := range suspiciousParents {
				if strings.Contains(parentLower, suspicious) {
					if isRoot {
						return 4, "Root shell spawned by " + suspicious + " (possible RCE)"
					}
					return 3, "Shell spawned by web/app server: " + suspicious
				}
			}
		}
	}

	// Shell from temporary directory (HIGH)
	if strings.Contains(filePath, "/tmp/") ||
		strings.Contains(filePath, "/var/tmp/") ||
		strings.Contains(filePath, "/dev/shm/") {
		return 3, "Shell execution from temporary directory"
	}

	// Interactive root shell (MEDIUM)
	if isRoot && strings.Contains(filePath, " -i") {
		return 2, "Interactive root shell"
	}

	// Root shell (MEDIUM) - unless from legitimate source
	if isRoot {
		// Check if from legitimate parent
		legitimateParents := []string{
			"sshd", "login", "su", "sudo", "cron", "systemd",
			"containerd", "docker", "runc",
		}
		if containerCtx != nil {
			if parentCmd, ok := containerCtx["parent_command"]; ok {
				for _, legit := range legitimateParents {
					if strings.Contains(strings.ToLower(parentCmd), legit) {
						return 1, "Root shell from legitimate source: " + legit
					}
				}
			}
		}
		return 2, "Root shell execution"
	}

	// Default: normal shell execution
	return 1, "Shell execution (" + command + ")"
}

// hasDownloadAndExecutePattern checks for curl/wget piped to shell
func (c *EventClassifier) hasDownloadAndExecutePattern(cmdLine string) bool {
	cmdLower := strings.ToLower(cmdLine)

	// curl/wget piped to shell
	patterns := []string{
		"curl", "wget",
	}
	pipeToShell := []string{
		"| bash", "|bash", "| sh", "|sh",
		"| /bin/bash", "| /bin/sh",
	}

	for _, dl := range patterns {
		if strings.Contains(cmdLower, dl) {
			for _, pipe := range pipeToShell {
				if strings.Contains(cmdLower, pipe) {
					return true
				}
			}
		}
	}

	// Also check for download to /tmp and execute pattern
	if (strings.Contains(cmdLower, "curl") || strings.Contains(cmdLower, "wget")) &&
		(strings.Contains(cmdLower, "/tmp/") || strings.Contains(cmdLower, "-o /tmp")) {
		return true
	}

	return false
}
