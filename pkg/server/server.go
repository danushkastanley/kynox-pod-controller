package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	pb "pod-controller/pkg/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type ConnectedAgent struct {
	AgentID   string
	NodeName  string
	PodName   string
	SessionID string
	LastSeen  time.Time
}

type TelemetryServer struct {
	pb.UnimplementedTelemetryServiceServer
	mu       sync.RWMutex
	agents   map[string]*ConnectedAgent // key: agent_id
	timeout  time.Duration              // timeout for inactive agents
	detector *ThreatDetector
}

func NewTelemetryServer(timeout time.Duration) *TelemetryServer {
	return &TelemetryServer{
		agents:   make(map[string]*ConnectedAgent),
		timeout:  timeout,
		detector: NewThreatDetector(),
	}
}

func (s *TelemetryServer) ConnectAgent(ctx context.Context, req *pb.ConnectRequest) (*pb.ConnectResponse, error) {
	if req.AgentId == "" {
		log.Printf("❌ Connection rejected: missing agent_id")
		return nil, status.Error(codes.InvalidArgument, "agent_id is required")
	}

	// Get peer info
	p, ok := peer.FromContext(ctx)
	clientAddr := "unknown"
	if ok {
		clientAddr = p.Addr.String()
	}

	sessionID := generateSessionID()
	agent := &ConnectedAgent{
		AgentID:   req.AgentId,
		NodeName:  req.NodeName,
		PodName:   req.PodName,
		SessionID: sessionID,
		LastSeen:  time.Now(),
	}

	s.mu.Lock()
	// Check if agent already exists
	if existingAgent, exists := s.agents[req.AgentId]; exists {
		log.Printf("⚠️  Agent %s reconnecting from %s (old session: %s)", req.AgentId, clientAddr, existingAgent.SessionID)
	} else {
		log.Printf("✅ New agent connecting from %s:", clientAddr)
		log.Printf("   Agent ID: %s", req.AgentId)
		log.Printf("   Node: %s", req.NodeName)
		log.Printf("   Pod: %s", req.PodName)
	}
	s.agents[req.AgentId] = agent
	s.mu.Unlock()

	return &pb.ConnectResponse{
		Success:   true,
		SessionId: sessionID,
	}, nil
}

func (s *TelemetryServer) SendHeartbeat(ctx context.Context, req *pb.Heartbeat) (*pb.ConnectionStatus, error) {
	s.mu.Lock()
	agent, exists := s.agents[req.AgentId]
	if !exists {
		s.mu.Unlock()
		log.Printf("❌ Heartbeat failed: unknown agent %s", req.AgentId)
		return &pb.ConnectionStatus{
			Status:       pb.ConnectionStatus_ERROR,
			AgentId:     req.AgentId,
			ErrorMessage: "agent not registered",
		}, nil
	}

	if agent.SessionID != req.SessionId {
		s.mu.Unlock()
		log.Printf("❌ Heartbeat failed: invalid session for agent %s (got: %s, want: %s)", 
			req.AgentId, req.SessionId, agent.SessionID)
		return &pb.ConnectionStatus{
			Status:       pb.ConnectionStatus_ERROR,
			AgentId:     req.AgentId,
			ErrorMessage: "invalid session",
		}, nil
	}

	lastSeen := agent.LastSeen
	agent.LastSeen = time.Now()
	s.mu.Unlock()

	// Log heartbeat but not too frequently to avoid spam
	if time.Since(lastSeen) > time.Second*30 {
		log.Printf("💓 Heartbeat from agent %s (node: %s, pod: %s)", 
			agent.AgentID, agent.NodeName, agent.PodName)
	}

	return &pb.ConnectionStatus{
		Status:   pb.ConnectionStatus_CONNECTED,
		AgentId:  req.AgentId,
	}, nil
}

func (s *TelemetryServer) StreamEvents(stream pb.TelemetryService_StreamEventsServer) error {
	// Get first event to identify the agent
	event, err := stream.Recv()
	if err != nil {
		return status.Error(codes.Internal, "failed to receive initial event")
	}

	// Verify agent is connected
	s.mu.RLock()
	agentID := event.ContainerContext["agent_id"]
	agent, exists := s.agents[agentID]
	s.mu.RUnlock()

	if !exists {
		return status.Error(codes.FailedPrecondition, "agent not connected")
	}

	// Process events
	for {
		if err := s.processEvent(event, agent); err != nil {
			return err
		}

		event, err = stream.Recv()
		if err != nil {
			return err
		}
	}
}

func (s *TelemetryServer) processEvent(event *pb.SecurityEvent, agent *ConnectedAgent) error {
	// Extract container context
	containerId := event.ContainerContext["container_id"]
	podName := event.ContainerContext["pod_name"]
	namespace := event.ContainerContext["namespace"]

	// Create base log fields
	fields := logrus.Fields{
		"agent_id":      agent.AgentID,
		"node":          agent.NodeName,
		"pod":          agent.PodName,
		"event_type":    event.GetEventType().String(),
		"pid":          event.GetPid(),
		"ppid":         event.GetPpid(),
		"uid":          event.GetUid(),
		"gid":          event.GetGid(),
		"command":      event.GetCommand(),
		"timestamp":    event.GetTimestamp().AsTime().Format(time.RFC3339),
		"container_id": containerId,
		"k8s_pod":     podName,
		"k8s_ns":      namespace,
	}

	// Add context-specific fields
	switch event.GetEventType() {
	case pb.EventType_EXEC:
		fields["file_path"] = event.GetFilePath()
	case pb.EventType_CONNECT, pb.EventType_BIND, pb.EventType_ACCEPT:
		fields["src_ip"] = event.GetSourceIp()
		fields["src_port"] = event.GetSourcePort()
		fields["dst_ip"] = event.GetDestinationIp()
		fields["dst_port"] = event.GetDestinationPort()
	case pb.EventType_OPEN:
		fields["file_path"] = event.GetFilePath()
	case pb.EventType_PTRACE:
		fields["ptrace_request"] = event.GetPtraceRequest()
		fields["ptrace_target"] = event.GetPtraceTargetPid()
	case pb.EventType_MOUNT, pb.EventType_UMOUNT:
		fields["file_path"] = event.GetFilePath()
	}

	// Threat detection logic
	var severity string
	var message string

	// Check for high-risk events first
	if s.detector.isPrivilegedOperation(event) {
		severity = "WARNING"
		message = "Privileged operation detected"
	}

	// Event-specific checks
	switch event.GetEventType() {
	case pb.EventType_EXEC:
		if s.detector.isSuspiciousCommand(event.GetCommand()) {
			severity = "WARNING"
			message = "Suspicious command execution detected"
		}
		if s.detector.detectAnomalousProcessSpawning(event, containerId) {
			severity = "WARNING"
			message = "Anomalous process spawning detected"
		}

	case pb.EventType_OPEN:
		if s.detector.isSuspiciousFileAccess(event.GetFilePath()) {
			severity = "WARNING"
			message = "Sensitive file access detected"
		}

	case pb.EventType_CONNECT:
		if s.detector.isExternalConnection(event.GetDestinationIp()) {
			severity = "WARNING"
			message = "External network connection detected"
		}
		if s.detector.detectAnomalousNetworkActivity(event, containerId) {
			severity = "WARNING"
			message = "Anomalous network activity detected"
		}

	case pb.EventType_PTRACE:
		if s.detector.isSuspiciousPtraceOperation(event.GetPtraceRequest(), event.GetPtraceTargetPid()) {
			severity = "CRITICAL"
			message = "Suspicious ptrace operation detected"
		}

	case pb.EventType_SETUID:
		if event.GetUid() == 0 {
			severity = "CRITICAL"
			message = "Potential privilege escalation detected"
		}

	case pb.EventType_MOUNT:
		if s.detector.isSuspiciousMount(event.GetFilePath()) {
			severity = "CRITICAL"
			message = "Suspicious mount operation detected"
		}

	case pb.EventType_BPF_PROG:
		severity = "CRITICAL"
		message = "BPF program loading detected"

	case pb.EventType_SECCOMP:
		severity = "WARNING"
		message = "Seccomp filter modification detected"
	}

	// Log with appropriate severity
	entry := logrus.WithFields(fields)
	if severity != "" {
		fields["alert"] = message
		switch severity {
		case "CRITICAL":
			entry.Error(message)
		case "WARNING":
			entry.Warn(message)
		default:
			entry.Info(message)
		}
	} else {
		entry.Info("Security event received")
	}

	return nil
}

func (s *TelemetryServer) CleanupInactiveAgents() {
	ticker := time.NewTicker(s.timeout / 2)
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, agent := range s.agents {
			if now.Sub(agent.LastSeen) > s.timeout {
				log.Printf("⚠️  Removing inactive agent %s (node: %s, pod: %s, last seen: %s ago)",
					id, agent.NodeName, agent.PodName, now.Sub(agent.LastSeen).Round(time.Second))
				delete(s.agents, id)
			}
		}
		s.mu.Unlock()
	}
}

func generateSessionID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
