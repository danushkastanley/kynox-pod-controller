package server

import (
	"net"
	"strings"
	"sync"
	"time"

	pb "pod-controller/pkg/telemetry"
)

// ThreatDetector handles threat detection logic
type ThreatDetector struct {
	mu sync.RWMutex
	// Track process spawn rate per container
	processSpawnCount map[string]*SpawnTracker
	// Track network connections per container
	networkConnCount map[string]*ConnectionTracker
}

type SpawnTracker struct {
	count     int
	startTime time.Time
}

type ConnectionTracker struct {
	connections map[string]int // destination -> count
	startTime   time.Time
}

func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		processSpawnCount: make(map[string]*SpawnTracker),
		networkConnCount:  make(map[string]*ConnectionTracker),
	}
}

// isPrivilegedOperation checks if an operation requires elevated privileges
func (td *ThreatDetector) isPrivilegedOperation(event *pb.SecurityEvent) bool {
	switch event.GetEventType() {
	case pb.EventType_SETUID, pb.EventType_SETGID:
		return true
	case pb.EventType_CAPSET:
		return true
	case pb.EventType_BPF_PROG, pb.EventType_SECCOMP:
		return true
	case pb.EventType_MOUNT, pb.EventType_UMOUNT:
		return true
	case pb.EventType_PTRACE:
		// Ptrace operations are always privileged
		return true
	default:
		return false
	}
}

// isSuspiciousCommand checks for known suspicious commands
func (td *ThreatDetector) IsSuspiciousCommand(cmd string) bool {
	suspiciousCommands := []string{
		// Network tools
		"nc", "netcat", "ncat", "socat",
		"wget", "curl", "telnet", "ftp",

		// Shells and interpreters
		"bash", "sh", "ash", "dash", "zsh",
		"python", "perl", "ruby", "php", "node",

		// System modification
		"chmod", "chown", "chattr",
		"mount", "umount",

		// Network analysis
		"tcpdump", "wireshark", "tshark",
		"nmap", "masscan", "netstat",

		// Process inspection
		"strace", "ltrace", "ptrace",
		"gdb", "lldb",

		// Container management tools (only suspicious in certain contexts)
		"docker", "kubectl", "crictl",
		"runc", "containerd", // Contextually suspicious - handled in classifier
		// Note: runc can be involved in container escapes

		// Crypto mining
		"minerd", "cpuminer", "xmrig",

		// File transfer
		"scp", "rsync", "sftp",
	}

	cmd = strings.ToLower(strings.TrimSpace(cmd))
	for _, suspicious := range suspiciousCommands {
		if strings.HasSuffix(cmd, suspicious) {
			return true
		}
	}
	return false
}

// isSuspiciousFileAccess checks if a file access is suspicious based on
// the path being accessed and any known sensitive files
func (td *ThreatDetector) IsSuspiciousFileAccess(path string) bool {
	sensitiveFiles := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/sudoers",
		"/etc/ssh/sshd_config",
		"/root/.ssh/authorized_keys",
		"/etc/kubernetes/admin.conf",
		"/etc/kubernetes/pki/",
		"/var/run/docker.sock",
	}

	for _, file := range sensitiveFiles {
		if strings.HasPrefix(path, file) {
			return true
		}
	}

	// Check for sensitive directories
	sensitiveDirs := []string{
		"/etc/ssl/private/",
		"/etc/ssl/certs/",
		"/etc/pki/",
		"/etc/security/",
		"/var/lib/kubelet/",
		"/var/lib/docker/",
	}

	for _, dir := range sensitiveDirs {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}

	return false
}

// isSuspiciousPtraceOperation checks for dangerous ptrace operations
func (td *ThreatDetector) isSuspiciousPtraceOperation(request int64, targetPid int32) bool {
	// PTRACE_POKETEXT, PTRACE_POKEDATA - Memory modification
	if request == 4 || request == 5 {
		return true
	}

	// PTRACE_ATTACH to privileged process
	if request == 16 && targetPid == 1 {
		return true
	}

	return false
}

// isSuspiciousMount checks for potentially dangerous mount operations
func (td *ThreatDetector) isSuspiciousMount(path string) bool {
	suspiciousMounts := []string{
		"/proc",
		"/sys",
		"/dev",
		"/var/run/docker.sock",
		"/etc/kubernetes",
	}

	for _, mount := range suspiciousMounts {
		if strings.HasPrefix(path, mount) {
			return true
		}
	}
	return false
}

// isExternalConnection checks if a connection is to an external IP
func (td *ThreatDetector) IsExternalConnection(ip string) bool {
	if ip == "" {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check if IP is private
	privateNetworks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, network := range privateNetworks {
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

// detectAnomalousProcessSpawning checks for unusual process spawn patterns
func (td *ThreatDetector) detectAnomalousProcessSpawning(event *pb.SecurityEvent, containerId string) bool {
	td.mu.Lock()
	defer td.mu.Unlock()

	// Use container ID from event context if available
	if containerCtx := event.GetContainerContext(); containerCtx != nil {
		if id := containerCtx["container_id"]; id != "" {
			containerId = id
		}
	}

	tracker, exists := td.processSpawnCount[containerId]
	if !exists {
		td.processSpawnCount[containerId] = &SpawnTracker{
			count:     1,
			startTime: time.Now(),
		}
		return false
	}

	// Reset counter if more than 60 seconds have passed
	if time.Since(tracker.startTime) > 60*time.Second {
		tracker.count = 1
		tracker.startTime = time.Now()
		return false
	}

	tracker.count++
	// Alert if more than 50 processes spawned within 60 seconds
	return tracker.count > 50
}

// detectAnomalousNetworkActivity checks for suspicious network patterns
func (td *ThreatDetector) detectAnomalousNetworkActivity(event *pb.SecurityEvent, containerId string) bool {
	td.mu.Lock()
	defer td.mu.Unlock()

	// Use container ID from event context if available
	if containerCtx := event.GetContainerContext(); containerCtx != nil {
		if id := containerCtx["container_id"]; id != "" {
			containerId = id
		}
	}

	tracker, exists := td.networkConnCount[containerId]
	if !exists {
		tracker = &ConnectionTracker{
			connections: make(map[string]int),
			startTime:   time.Now(),
		}
		td.networkConnCount[containerId] = tracker
	}

	// Reset if more than 60 seconds have passed
	if time.Since(tracker.startTime) > 60*time.Second {
		tracker.connections = make(map[string]int)
		tracker.startTime = time.Now()
	}

	dst := event.GetDestinationIp()
	if dst != "" {
		tracker.connections[dst]++
		// Alert if container connects to more than 20 unique IPs within 60 seconds
		return len(tracker.connections) > 20
	}

	return false
}

// isSuspiciousChmod checks if a chmod operation is suspicious based on:
// 1. The target file being sensitive
// 2. The permissions being overly permissive (world-writable)
func (td *ThreatDetector) IsSuspiciousChmod(path string, mode uint32) bool {
	// Check if target is a sensitive file
	if td.IsSuspiciousFileAccess(path) {
		return true
	}

	// Check for world-writable permissions (0777, 0666, etc)
	worldWritable := mode&0002 != 0
	if worldWritable {
		// Get just the permission bits, ignoring special bits
		perms := mode & 0777

		// Check for especially dangerous combinations:
		// - World writable and executable (777)
		// - World writable on sensitive paths
		if perms == 0777 || strings.HasPrefix(path, "/etc/") ||
			strings.HasPrefix(path, "/usr/") || strings.HasPrefix(path, "/bin/") {
			return true
		}
	}

	return false
}
