package detection

import (
	"strings"

	pb "github.com/danushkastanley/rasp-controller/pkg/api/proto"
)

// ThreatLevel represents the severity of a detected threat
type ThreatLevel string

const (
	ThreatLevelLow    ThreatLevel = "LOW"
	ThreatLevelMedium ThreatLevel = "MEDIUM"
	ThreatLevelHigh   ThreatLevel = "HIGH"
)

// Engine handles threat detection logic
type Engine struct {
	// Add configuration fields here
	suspiciousCommands map[string]ThreatLevel
}

// NewEngine creates a new detection engine instance
func NewEngine() *Engine {
	return &Engine{
		suspiciousCommands: map[string]ThreatLevel{
			"nc":     ThreatLevelHigh,
			"netcat": ThreatLevelHigh,
			"curl":   ThreatLevelMedium,
			"wget":   ThreatLevelMedium,
			"bash":   ThreatLevelMedium,
			"sh":     ThreatLevelMedium,
			"python": ThreatLevelMedium,
			"perl":   ThreatLevelMedium,
		},
	}
}

// Analyze evaluates a security event and returns a threat level
func (e *Engine) Analyze(event *pb.SecurityEvent) ThreatLevel {
	if event == nil || event.Process == nil {
		return ThreatLevelLow
	}

	// Check for high-risk conditions first
	if e.isHighRiskEvent(event) {
		return ThreatLevelHigh
	}

	// Check for suspicious commands
	if level := e.checkSuspiciousCommand(event); level != ThreatLevelLow {
		return level
	}

	// Check for network activity
	if level := e.checkNetworkActivity(event); level != ThreatLevelLow {
		return level
	}

	return ThreatLevelLow
}

// isHighRiskEvent checks for inherently high-risk events
func (e *Engine) isHighRiskEvent(event *pb.SecurityEvent) bool {
	// Check for root/privileged operations
	if event.Process.GetUid() == 0 {
		return true
	}

	// Check high-risk event types
	switch event.EventType {
	case pb.EventType_SETUID,
		pb.EventType_MOUNT,
		pb.EventType_BPF_PROG,
		pb.EventType_PTRACE:
		return true
	}

	return false
}

// checkSuspiciousCommand evaluates the command and its arguments
func (e *Engine) checkSuspiciousCommand(event *pb.SecurityEvent) ThreatLevel {
	if event.EventType != pb.EventType_EXEC {
		return ThreatLevelLow
	}

	cmd := strings.ToLower(event.Process.GetCommand())
	
	// Check base command
	if level, found := e.suspiciousCommands[cmd]; found {
		return level
	}

	// Check command arguments for suspicious patterns
	for _, arg := range event.Process.GetArgs() {
		arg = strings.ToLower(arg)
		if strings.Contains(arg, "wget") || strings.Contains(arg, "curl") {
			return ThreatLevelMedium
		}
		if strings.Contains(arg, "nc") || strings.Contains(arg, "netcat") {
			return ThreatLevelHigh
		}
	}

	return ThreatLevelLow
}

// checkNetworkActivity evaluates network-related events
func (e *Engine) checkNetworkActivity(event *pb.SecurityEvent) ThreatLevel {
	if event.EventType != pb.EventType_CONNECT {
		return ThreatLevelLow
	}

	// Get network details if available
	if details := event.GetNetworkInfo(); details != nil {
		// Check for suspicious ports
		if details.GetPort() <= 1024 {
			return ThreatLevelMedium
		}

		// Check for raw sockets
		if details.GetProtocol() == "RAW" {
			return ThreatLevelHigh
		}
	}

	return ThreatLevelLow
}
