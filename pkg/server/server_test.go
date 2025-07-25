package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"pod-controller/pkg/common"
	pb "pod-controller/pkg/telemetry"
)

// MockClassifier for testing
type MockClassifier struct {
	mock.Mock
}

func (m *MockClassifier) ClassifyEvent(event *pb.SecurityEvent) (common.Severity, string) {
	args := m.Called(event)
	return args.Get(0).(common.Severity), args.String(1)
}

func TestNewTelemetryServer(t *testing.T) {
	server := NewTelemetryServer(5 * time.Minute)

	assert.NotNil(t, server)
	assert.NotNil(t, server.agents)
	assert.NotNil(t, server.eventCounts)
	assert.NotNil(t, server.severityCounts)
	assert.NotNil(t, server.alertAggregation)
	assert.Equal(t, 5*time.Minute, server.timeout)
}

func TestConnectAgent(t *testing.T) {
	server := NewTelemetryServer(5 * time.Minute)
	ctx := context.Background()

	tests := []struct {
		name     string
		request  *pb.ConnectRequest
		expected bool
	}{
		{
			name: "valid agent connection",
			request: &pb.ConnectRequest{
				AgentId:  "test-agent-1",
				NodeName: "test-node",
				PodName:  "test-pod",
			},
			expected: true,
		},
		{
			name: "empty agent id",
			request: &pb.ConnectRequest{
				AgentId:  "",
				NodeName: "test-node",
				PodName:  "test-pod",
			},
			expected: false,
		},
		{
			name: "duplicate agent connection",
			request: &pb.ConnectRequest{
				AgentId:  "test-agent-1", // Same as first test
				NodeName: "test-node-2",
				PodName:  "test-pod-2",
			},
			expected: true, // Should allow reconnection
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := server.ConnectAgent(ctx, tt.request)

			if tt.expected {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Success)
				assert.NotEmpty(t, resp.SessionId)

				// Verify agent was registered
				server.mu.RLock()
				agent, exists := server.agents[tt.request.AgentId]
				server.mu.RUnlock()

				assert.True(t, exists)
				assert.Equal(t, tt.request.AgentId, agent.AgentID)
				assert.Equal(t, tt.request.NodeName, agent.NodeName)
				assert.Equal(t, tt.request.PodName, agent.PodName)
			} else {
				assert.Error(t, err)
				assert.Nil(t, resp) // resp should be nil when there's an error
			}
		})
	}
}

func TestSendHeartbeat(t *testing.T) {
	server := NewTelemetryServer(5 * time.Minute)
	ctx := context.Background()

	// First, register an agent
	connectReq := &pb.ConnectRequest{
		AgentId:  "test-agent",
		NodeName: "test-node",
		PodName:  "test-pod",
	}
	connectResp, err := server.ConnectAgent(ctx, connectReq)
	require.NoError(t, err)
	require.True(t, connectResp.Success)

	tests := []struct {
		name      string
		request   *pb.Heartbeat
		expectErr bool
	}{
		{
			name: "valid heartbeat",
			request: &pb.Heartbeat{
				AgentId:   "test-agent",
				SessionId: connectResp.SessionId,
			},
			expectErr: false,
		},
		{
			name: "invalid agent id",
			request: &pb.Heartbeat{
				AgentId:   "non-existent-agent",
				SessionId: connectResp.SessionId,
			},
			expectErr: true,
		},
		{
			name: "invalid session id",
			request: &pb.Heartbeat{
				AgentId:   "test-agent",
				SessionId: "invalid-session",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := server.SendHeartbeat(ctx, tt.request)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, pb.ConnectionStatus_CONNECTED, resp.Status)
			}
		})
	}
}

func TestProcessEvent(t *testing.T) {
	// Create mock dependencies
	mockClassifier := new(MockClassifier)

	server := NewTelemetryServer(5 * time.Minute)
	server.classifier = mockClassifier
	// Note: For this test, we'll use the real alerter but verify behavior through metrics

	// Create test agent
	agent := &ConnectedAgent{
		AgentID:   "test-agent",
		NodeName:  "test-node",
		PodName:   "test-pod",
		SessionID: "test-session",
		LastSeen:  time.Now(),
	}

	tests := []struct {
		name           string
		event          *pb.SecurityEvent
		expectedSev    common.Severity
		expectedMsg    string
		shouldAlert    bool
		expectedAlerts int
	}{
		{
			name: "critical event",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_SETUID,
				Pid:       1234,
				Command:   "malicious_binary",
				Uid:       0,
				Timestamp: timestamppb.Now(),
				ContainerContext: map[string]string{
					"container_id": "abc123",
					"namespace":    "default",
					"pod_name":     "test-pod",
				},
			},
			expectedSev:    common.SeverityCritical,
			expectedMsg:    "Root privilege escalation detected",
			shouldAlert:    true,
			expectedAlerts: 1,
		},
		{
			name: "low severity event",
			event: &pb.SecurityEvent{
				EventType: pb.EventType_OPEN,
				Pid:       1234,
				Command:   "cat",
				FilePath:  "/etc/hostname",
				Timestamp: timestamppb.Now(),
			},
			expectedSev:    common.SeverityLow,
			expectedMsg:    "File access",
			shouldAlert:    false,
			expectedAlerts: 0,
		},
		{
			name: "network connection event",
			event: &pb.SecurityEvent{
				EventType:       pb.EventType_CONNECT,
				Pid:             1234,
				Command:         "curl",
				DestinationIp:   "8.8.8.8",
				DestinationPort: 80,
				Timestamp:       timestamppb.Now(),
			},
			expectedSev:    common.SeverityWarn,
			expectedMsg:    "External network connection",
			shouldAlert:    true,
			expectedAlerts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock expectations
			mockClassifier.On("ClassifyEvent", tt.event).Return(tt.expectedSev, tt.expectedMsg).Once()

			// Process the event
			err := server.processEvent(tt.event, agent)
			assert.NoError(t, err)

			// Verify mock expectations
			mockClassifier.AssertExpectations(t)

			// Reset mocks for next test
			mockClassifier.ExpectedCalls = nil
		})
	}
}

func TestUpdateMetrics(t *testing.T) {
	server := NewTelemetryServer(5 * time.Minute)

	// Test metric updates
	server.updateMetrics("EXEC", common.SeverityHigh)
	server.updateMetrics("OPEN", common.SeverityLow)
	server.updateMetrics("EXEC", common.SeverityCritical)

	metrics := server.GetMetrics()

	assert.Equal(t, int64(2), metrics["event_counts"].(map[string]int64)["EXEC"])
	assert.Equal(t, int64(1), metrics["event_counts"].(map[string]int64)["OPEN"])
	assert.Equal(t, int64(1), metrics["severity_counts"].(map[string]int64)["HIGH"])
	assert.Equal(t, int64(1), metrics["severity_counts"].(map[string]int64)["LOW"])
	assert.Equal(t, int64(1), metrics["severity_counts"].(map[string]int64)["CRITICAL"])
}

func TestAlertAggregation(t *testing.T) {
	server := NewTelemetryServer(5 * time.Minute)

	key := AlertKey{
		EventType:   "EXEC",
		Command:     "test-command",
		Namespace:   "default",
		PodName:     "test-pod",
		ContainerID: "abc123",
		Severity:    "HIGH",
	}

	// First alert should be sent
	shouldSend := server.aggregateAlert(key, "Test message")
	assert.True(t, shouldSend)

	// Immediate second alert should be aggregated
	shouldSend = server.aggregateAlert(key, "Test message")
	assert.False(t, shouldSend)

	// Check aggregation state
	server.aggregationMu.RLock()
	agg, exists := server.alertAggregation[key]
	server.aggregationMu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, 2, agg.Count)
}

func TestCleanupInactiveAgents(t *testing.T) {
	server := NewTelemetryServer(1 * time.Second) // Short timeout for testing
	ctx := context.Background()

	// Register agents
	agent1 := &pb.ConnectRequest{AgentId: "agent1", NodeName: "node1", PodName: "pod1"}
	agent2 := &pb.ConnectRequest{AgentId: "agent2", NodeName: "node2", PodName: "pod2"}

	_, err := server.ConnectAgent(ctx, agent1)
	require.NoError(t, err)
	_, err = server.ConnectAgent(ctx, agent2)
	require.NoError(t, err)

	// Verify both agents are registered
	server.mu.RLock()
	assert.Len(t, server.agents, 2)
	server.mu.RUnlock()

	// Make one agent inactive by setting old LastSeen
	server.mu.Lock()
	server.agents["agent1"].LastSeen = time.Now().Add(-2 * time.Second)
	server.mu.Unlock()

	// Run cleanup
	server.CleanupInactiveAgents()

	// Verify only active agent remains
	server.mu.RLock()
	assert.Len(t, server.agents, 1)
	_, exists := server.agents["agent2"]
	assert.True(t, exists)
	_, exists = server.agents["agent1"]
	assert.False(t, exists)
	server.mu.RUnlock()
}

func TestGetMetrics(t *testing.T) {
	server := NewTelemetryServer(5 * time.Minute)

	// Add some test data
	server.updateMetrics("EXEC", common.SeverityHigh)
	server.updateMetrics("OPEN", common.SeverityLow)

	// Register an agent
	ctx := context.Background()
	req := &pb.ConnectRequest{
		AgentId:  "test-agent",
		NodeName: "test-node",
		PodName:  "test-pod",
	}
	_, err := server.ConnectAgent(ctx, req)
	require.NoError(t, err)

	metrics := server.GetMetrics()

	assert.Contains(t, metrics, "uptime_seconds")
	assert.Contains(t, metrics, "connected_agents")
	assert.Contains(t, metrics, "total_events")
	assert.Contains(t, metrics, "event_counts")
	assert.Contains(t, metrics, "severity_counts")

	assert.Equal(t, 1, metrics["connected_agents"])
	assert.Equal(t, int64(2), metrics["total_events"])
}

func BenchmarkProcessEvent(b *testing.B) {
	mockClassifier := new(MockClassifier)

	server := NewTelemetryServer(5 * time.Minute)
	server.classifier = mockClassifier

	agent := &ConnectedAgent{
		AgentID:   "benchmark-agent",
		NodeName:  "benchmark-node",
		PodName:   "benchmark-pod",
		SessionID: "benchmark-session",
		LastSeen:  time.Now(),
	}

	event := &pb.SecurityEvent{
		EventType: pb.EventType_EXEC,
		Pid:       1234,
		Command:   "test-command",
		Timestamp: timestamppb.Now(),
	}

	// Set up mock to always return low severity
	mockClassifier.On("ClassifyEvent", mock.Anything).Return(common.SeverityLow, "test").Maybe()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.processEvent(event, agent)
	}
}
