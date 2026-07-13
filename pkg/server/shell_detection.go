package server

import (
	"regexp"
	"strings"

	pb "pod-controller/pkg/telemetry"
)

// ShellDetector provides context-aware shell execution detection
type ShellDetector struct {
	// Shells that we track
	shells map[string]bool

	// Parent processes that should NOT spawn shells (suspicious if they do)
	suspiciousParents map[string]bool

	// Parent processes that legitimately spawn shells
	legitimateParents map[string]bool

	// Suspicious command argument patterns
	suspiciousArgPatterns []*regexp.Regexp

	// Highly suspicious patterns (almost always malicious)
	maliciousPatterns []*regexp.Regexp
}

// ShellContext holds contextual information about a shell execution
type ShellContext struct {
	Command       string
	ParentCommand string
	FilePath      string
	UID           int32
	IsInteractive bool
	HasPipe       bool
	IsDownloader  bool
	IsReverse     bool
}

// ShellRisk represents the risk level of a shell execution
type ShellRisk int

const (
	ShellRiskNone     ShellRisk = iota // Not a shell or clearly legitimate
	ShellRiskLow                       // Shell execution, but likely legitimate
	ShellRiskMedium                    // Potentially suspicious, worth logging
	ShellRiskHigh                      // Likely malicious
	ShellRiskCritical                  // Almost certainly malicious
)

func (r ShellRisk) String() string {
	switch r {
	case ShellRiskNone:
		return "NONE"
	case ShellRiskLow:
		return "LOW"
	case ShellRiskMedium:
		return "MEDIUM"
	case ShellRiskHigh:
		return "HIGH"
	case ShellRiskCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// NewShellDetector creates a new context-aware shell detector
func NewShellDetector() *ShellDetector {
	sd := &ShellDetector{
		shells: map[string]bool{
			"bash":    true,
			"sh":      true,
			"dash":    true,
			"ash":     true,
			"zsh":     true,
			"ksh":     true,
			"csh":     true,
			"tcsh":    true,
			"fish":    true,
			"busybox": true, // Often used as shell
		},

		// Web servers / application servers spawning shells is suspicious
		suspiciousParents: map[string]bool{
			// Web servers
			"nginx":    true,
			"apache":   true,
			"apache2":  true,
			"httpd":    true,
			"lighttpd": true,
			"caddy":    true,

			// Application servers / runtimes
			"java":     true,
			"node":     true,
			"nodejs":   true,
			"python":   true,
			"python3":  true,
			"ruby":     true,
			"php":      true,
			"php-fpm":  true,
			"gunicorn": true,
			"uwsgi":    true,
			"unicorn":  true,
			"puma":     true,
			"tomcat":   true,
			"jetty":    true,
			"weblogic": true,
			"jboss":    true,

			// Databases (shell from DB = SQL injection -> RCE)
			"postgres":     true,
			"mysql":        true,
			"mysqld":       true,
			"mongod":       true,
			"redis-server": true,
		},

		// These processes legitimately spawn shells
		legitimateParents: map[string]bool{
			// Init systems
			"systemd":         true,
			"init":            true,
			"containerd":      true,
			"containerd-shim": true,
			"dockerd":         true,
			"docker":          true,
			"runc":            true,
			"cri-o":           true,
			"conmon":          true,

			// Remote access (expected to spawn shells)
			"sshd":   true,
			"login":  true,
			"su":     true,
			"sudo":   true,
			"screen": true,
			"tmux":   true,

			// CI/CD and automation
			"jenkins":       true,
			"gitlab-runner": true,
			"drone":         true,
			"ansible":       true,

			// Shells spawning shells is normal
			"bash": true,
			"sh":   true,
			"zsh":  true,

			// Cron and schedulers
			"cron":    true,
			"crond":   true,
			"anacron": true,

			// Package managers
			"apt":     true,
			"apt-get": true,
			"yum":     true,
			"dnf":     true,
			"apk":     true,
		},
	}

	// Compile suspicious argument patterns
	sd.suspiciousArgPatterns = []*regexp.Regexp{
		// Interactive shells in non-interactive context
		regexp.MustCompile(`-i\s*$`), // bash -i
		regexp.MustCompile(`--interactive`),

		// Download and execute patterns
		regexp.MustCompile(`curl.*\|\s*(ba)?sh`), // curl ... | bash
		regexp.MustCompile(`wget.*\|\s*(ba)?sh`), // wget ... | bash
		regexp.MustCompile(`curl.*-o\s*/tmp/`),   // Download to /tmp
		regexp.MustCompile(`wget.*-O\s*/tmp/`),   // Download to /tmp

		// Base64 decode and execute
		regexp.MustCompile(`base64\s+-d`),
		regexp.MustCompile(`base64\s+--decode`),

		// Python/Perl one-liners often used for reverse shells
		regexp.MustCompile(`python.*-c.*socket`),
		regexp.MustCompile(`perl.*-e.*socket`),
		regexp.MustCompile(`ruby.*-e.*socket`),

		// Process substitution tricks
		regexp.MustCompile(`/dev/tcp/`),
		regexp.MustCompile(`/dev/udp/`),

		// History evasion
		regexp.MustCompile(`unset\s+HISTFILE`),
		regexp.MustCompile(`HISTFILE=/dev/null`),
		regexp.MustCompile(`history\s+-c`),
	}

	// Highly malicious patterns (almost always an attack)
	sd.maliciousPatterns = []*regexp.Regexp{
		// Reverse shell patterns
		regexp.MustCompile(`nc\s+.*-e\s+/bin`), // nc -e /bin/sh
		regexp.MustCompile(`ncat\s+.*-e\s+/bin`),
		regexp.MustCompile(`bash\s+-i\s+>&\s*/dev/tcp`), // bash -i >& /dev/tcp
		regexp.MustCompile(`exec\s+\d+<>/dev/tcp`),
		regexp.MustCompile(`mkfifo.*nc.*sh`), // Named pipe reverse shell

		// Python reverse shells
		regexp.MustCompile(`python.*import\s+socket.*connect`),
		regexp.MustCompile(`python.*import\s+pty.*spawn`),

		// Perl reverse shells
		regexp.MustCompile(`perl.*socket.*SOCK_STREAM`),

		// PHP reverse shells
		regexp.MustCompile(`php.*fsockopen`),

		// Metasploit patterns
		regexp.MustCompile(`meterpreter`),
		regexp.MustCompile(`payload.*reverse`),

		// Crypto miner execution
		regexp.MustCompile(`xmrig`),
		regexp.MustCompile(`minerd`),
		regexp.MustCompile(`stratum\+tcp://`),
	}

	return sd
}

// IsShell checks if a command is a shell
func (sd *ShellDetector) IsShell(command string) bool {
	cmd := strings.ToLower(strings.TrimSpace(command))
	// Check exact match or path ending
	for shell := range sd.shells {
		if cmd == shell || strings.HasSuffix(cmd, "/"+shell) {
			return true
		}
	}
	return false
}

// AnalyzeShellExecution performs context-aware analysis of shell execution
func (sd *ShellDetector) AnalyzeShellExecution(event *pb.SecurityEvent) (ShellRisk, string) {
	command := event.GetCommand()
	filePath := event.GetFilePath() // Contains full command with args for EXEC events

	// Not a shell? Not our concern
	if !sd.IsShell(command) {
		return ShellRiskNone, ""
	}

	// Check for malicious patterns first (highest priority)
	for _, pattern := range sd.maliciousPatterns {
		if pattern.MatchString(filePath) {
			return ShellRiskCritical, "Malicious shell pattern detected: " + pattern.String()
		}
	}

	// Check for suspicious argument patterns
	for _, pattern := range sd.suspiciousArgPatterns {
		if pattern.MatchString(filePath) {
			return ShellRiskHigh, "Suspicious shell arguments: " + pattern.String()
		}
	}

	// Get parent process info from container context
	containerCtx := event.GetContainerContext()
	parentCmd := ""
	if containerCtx != nil {
		if p, ok := containerCtx["parent_command"]; ok {
			parentCmd = strings.ToLower(p)
		}
	}

	// Check parent process
	if parentCmd != "" {
		// Web server/app spawning shell = likely web shell/RCE
		for suspicious := range sd.suspiciousParents {
			if strings.Contains(parentCmd, suspicious) {
				// Root makes it worse
				if event.GetUid() == 0 {
					return ShellRiskCritical, "Root shell spawned by " + suspicious + " (possible RCE)"
				}
				return ShellRiskHigh, "Shell spawned by web/app server: " + suspicious
			}
		}

		// Legitimate parent = lower risk
		for legitimate := range sd.legitimateParents {
			if strings.Contains(parentCmd, legitimate) {
				return ShellRiskLow, "Shell spawned by legitimate process: " + legitimate
			}
		}
	}

	// Check for shells in suspicious locations
	if strings.Contains(filePath, "/tmp/") ||
		strings.Contains(filePath, "/var/tmp/") ||
		strings.Contains(filePath, "/dev/shm/") {
		return ShellRiskHigh, "Shell execution from temporary directory"
	}

	// Interactive shell as root
	if event.GetUid() == 0 && strings.Contains(filePath, "-i") {
		return ShellRiskMedium, "Interactive root shell"
	}

	// Default: shell execution is low risk without other signals
	return ShellRiskLow, "Standard shell execution"
}

// AnalyzeExecEvent analyzes any exec event for shell-related risks
func (sd *ShellDetector) AnalyzeExecEvent(event *pb.SecurityEvent) (ShellRisk, string) {
	// Only for EXEC events
	if event.GetEventType() != pb.EventType_EXEC {
		return ShellRiskNone, ""
	}

	filePath := event.GetFilePath()

	// Even non-shell commands can be suspicious
	// Check for common attack patterns in any execution
	for _, pattern := range sd.maliciousPatterns {
		if pattern.MatchString(filePath) {
			return ShellRiskCritical, "Malicious command pattern: " + pattern.String()
		}
	}

	// If it's a shell, do full analysis
	if sd.IsShell(event.GetCommand()) {
		return sd.AnalyzeShellExecution(event)
	}

	return ShellRiskNone, ""
}

// Global shell detector instance
var globalShellDetector *ShellDetector

func GetShellDetector() *ShellDetector {
	if globalShellDetector == nil {
		globalShellDetector = NewShellDetector()
	}
	return globalShellDetector
}
