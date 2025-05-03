package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"pod-controller/pkg/alert"
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
	Metadata  map[string]string
}

type TelemetryServer struct {
	pb.UnimplementedTelemetryServiceServer
	mu        sync.RWMutex
	agents    map[string]*ConnectedAgent // key: agent_id
	timeout   time.Duration              // timeout for inactive agents
	detector  *ThreatDetector
	alerter   *alert.AlertDispatcher
}

func NewTelemetryServer(timeout time.Duration) *TelemetryServer {
	// Initialize alert dispatcher
	alertDispatcher, err := alert.NewAlertDispatcher()
	if err != nil {
		logrus.Fatalf("Failed to initialize alert dispatcher: %v", err)
	}

	return &TelemetryServer{
		agents:    make(map[string]*ConnectedAgent),
		timeout:   timeout,
		detector:  NewThreatDetector(),
		alerter:   alertDispatcher,
	}
}

func (s *TelemetryServer) ConnectAgent(ctx context.Context, req *pb.ConnectRequest) (*pb.ConnectResponse, error) {
	if req.AgentId == "" {
		logrus.Printf("❌ Connection rejected: missing agent_id")
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
		Metadata:  make(map[string]string),
	}

	s.mu.Lock()
	// Check if agent already exists
	if existingAgent, exists := s.agents[req.AgentId]; exists {
		logrus.Printf("⚠️  Agent %s reconnecting from %s (old session: %s)", req.AgentId, clientAddr, existingAgent.SessionID)
	} else {
		logrus.Printf("✅ New agent connecting from %s:", clientAddr)
		logrus.Printf("   Agent ID: %s", req.AgentId)
		logrus.Printf("   Node: %s", req.NodeName)
		logrus.Printf("   Pod: %s", req.PodName)
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
		logrus.Printf("❌ Heartbeat failed: unknown agent %s", req.AgentId)
		return &pb.ConnectionStatus{
			Status:       pb.ConnectionStatus_ERROR,
			AgentId:     req.AgentId,
			ErrorMessage: "agent not registered",
		}, nil
	}

	if agent.SessionID != req.SessionId {
		s.mu.Unlock()
		logrus.Printf("❌ Heartbeat failed: invalid session for agent %s (got: %s, want: %s)", 
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
		logrus.Printf("💓 Heartbeat from agent %s (node: %s, pod: %s)", 
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
			if err.Error() == "EOF" {
				// Client closed the stream normally
				return nil
			}
			return err
		}
	}
}

func (s *TelemetryServer) processEvent(event *pb.SecurityEvent, agent *ConnectedAgent) error {
	logrus.WithFields(logrus.Fields{
		"event_type": event.EventType.String(),
		"command":    event.Command,
		"pod":       event.ContainerContext["pod_name"],
		"node":      event.ContainerContext["node_name"],
	}).Debug("Received security event")

	// Extract container context
	containerId := event.ContainerContext["container_id"]
	podName := event.ContainerContext["pod_name"]
	namespace := event.ContainerContext["namespace"]

	// Create base log fields
	fields := logrus.Fields{
		"agent_id":      agent.AgentID,
		"node":          agent.NodeName,
		"pod":          agent.PodName,
		"event_type":    event.EventType.String(),
		"pid":          event.Pid,
		"ppid":         event.Ppid,
		"uid":          event.Uid,
		"gid":          event.Gid,
		"command":      event.Command,
		"timestamp":    event.Timestamp.AsTime().Format(time.RFC3339),
		"container_id": containerId,
		"k8s_pod":     podName,
		"k8s_ns":      namespace,
	}

	// Add context-specific fields
	switch event.EventType {
	case pb.EventType_EXEC:
		fields["file_path"] = event.FilePath
	case pb.EventType_CONNECT, pb.EventType_BIND, pb.EventType_ACCEPT:
		fields["src_ip"] = event.SourceIp
		fields["src_port"] = event.SourcePort
		fields["dst_ip"] = event.DestinationIp
		fields["dst_port"] = event.DestinationPort
	case pb.EventType_OPEN:
		fields["file_path"] = event.FilePath
	case pb.EventType_PTRACE:
		fields["ptrace_request"] = event.PtraceRequest
		fields["ptrace_target"] = event.PtraceTargetPid
	case pb.EventType_MOUNT, pb.EventType_UMOUNT:
		fields["file_path"] = event.FilePath
	}

	// Threat detection logic
	var severity string
	var message string
	var alertLevel alert.AlertLevel

	// Check for high-risk events first
	if s.detector.isPrivilegedOperation(event) {
		severity = "HIGH"
		message = "Privileged operation detected"
		alertLevel = alert.AlertLevelHigh
	}

	// Event-specific checks
	switch event.EventType {
	case pb.EventType_EXEC:
		if s.detector.isSuspiciousCommand(event.Command) {
			if event.Uid == 0 {
				severity = "CRITICAL"
				message = fmt.Sprintf("Root execution of suspicious command: %s", event.Command)
				alertLevel = alert.AlertLevelCritical
			} else {
				severity = "HIGH"
				message = fmt.Sprintf("Suspicious command execution: %s", event.Command)
				alertLevel = alert.AlertLevelHigh
			}
		}
		if s.detector.detectAnomalousProcessSpawning(event, containerId) {
			severity = "HIGH"
			message = "Anomalous process spawning detected"
			alertLevel = alert.AlertLevelHigh
		}

	case pb.EventType_OPEN:
		if s.detector.isSuspiciousFileAccess(event.FilePath) {
			severity = "HIGH"
			message = "Sensitive file access detected"
			alertLevel = alert.AlertLevelHigh
		}

	case pb.EventType_CONNECT:
		if s.detector.isExternalConnection(event.DestinationIp) {
			// Network tools run as root are especially concerning
			if event.Uid == 0 && s.detector.isSuspiciousCommand(event.Command) {
				severity = "CRITICAL"
				message = fmt.Sprintf("Root initiated external connection using %s to %s:%d", 
					event.Command, event.DestinationIp, event.DestinationPort)
				alertLevel = alert.AlertLevelCritical
			} else {
				severity = "HIGH"
				message = fmt.Sprintf("External connection detected to %s:%d", 
					event.DestinationIp, event.DestinationPort)
				alertLevel = alert.AlertLevelHigh
			}
		}
		if s.detector.detectAnomalousNetworkActivity(event, containerId) {
			severity = "CRITICAL"
			message = "Potential network scanning detected"
			alertLevel = alert.AlertLevelCritical
		}

	case pb.EventType_PTRACE:
		if s.detector.isSuspiciousPtraceOperation(event.PtraceRequest, event.PtraceTargetPid) {
			severity = "CRITICAL"
			message = "Memory modification attempt detected"
			alertLevel = alert.AlertLevelCritical
		} else {
			severity = "HIGH"
			message = "Process debugging detected"
			alertLevel = alert.AlertLevelHigh
		}

	case pb.EventType_SETUID:
		if event.Uid == 0 {
			severity = "CRITICAL"
			message = "Root privilege escalation detected"
			alertLevel = alert.AlertLevelCritical
		} else {
			severity = "HIGH"
			message = "User privilege change detected"
			alertLevel = alert.AlertLevelHigh
		}

	case pb.EventType_MOUNT:
		if s.detector.isSuspiciousMount(event.FilePath) {
			severity = "CRITICAL"
			message = "Sensitive filesystem mount detected"
			alertLevel = alert.AlertLevelCritical
		} else {
			severity = "HIGH"
			message = "Filesystem mount detected"
			alertLevel = alert.AlertLevelHigh
		}

	case pb.EventType_BPF_PROG:
		if event.Uid == 0 {
			severity = "CRITICAL"
			message = "Root BPF program loading detected"
			alertLevel = alert.AlertLevelCritical
		} else {
			severity = "HIGH"
			message = "BPF program loading detected"
			alertLevel = alert.AlertLevelHigh
		}

	case pb.EventType_SECCOMP:
		severity = "HIGH"
		message = "Seccomp filter modification detected"
		alertLevel = alert.AlertLevelHigh
	}

	// Log with appropriate severity
	entry := logrus.WithFields(fields)
	if severity != "" {
		fields["alert"] = message
		switch severity {
		case "CRITICAL":
			entry.Error(message)
		case "HIGH":
			entry.Warn(message)
		default:
			entry.Info(message)
		}

		// Create and dispatch alert for HIGH and CRITICAL events
		if alertLevel != "" {
			alertContext := map[string]string{
				"agent_id":     agent.AgentID,
				"node_name":    agent.NodeName,
				"pod_name":     agent.PodName,
				"container_id": containerId,
				"namespace":    namespace,
				"event_type":   event.EventType.String(),
				"command":      event.Command,
			}

			// Add process info
			alertContext["proc_pid"] = fmt.Sprintf("%d", event.Pid)
			alertContext["proc_ppid"] = fmt.Sprintf("%d", event.Ppid)
			alertContext["proc_uid"] = fmt.Sprintf("%d", event.Uid)
			alertContext["proc_gid"] = fmt.Sprintf("%d", event.Gid)

			// Add network info if present
			if event.SourceIp != "" {
				alertContext["net_src_ip"] = event.SourceIp
				alertContext["net_src_port"] = fmt.Sprintf("%d", event.SourcePort)
			}
			if event.DestinationIp != "" {
				alertContext["net_dst_ip"] = event.DestinationIp
				alertContext["net_dst_port"] = fmt.Sprintf("%d", event.DestinationPort)
			}

			// Add file info if present
			if event.FilePath != "" {
				alertContext["file_path"] = event.FilePath
			}

			// Add security info if present
			if event.PtraceRequest != 0 {
				alertContext["sec_ptrace_req"] = fmt.Sprintf("%d", event.PtraceRequest)
				alertContext["sec_ptrace_target"] = fmt.Sprintf("%d", event.PtraceTargetPid)
			}

			alert := alert.CreateAlert(
				alertLevel,
				fmt.Sprintf("%s: %s", severity, message),
				fmt.Sprintf("Security event detected in pod %s/%s on node %s", namespace, podName, agent.NodeName),
				alertContext,
			)

			if err := s.alerter.Dispatch(alert); err != nil {
				entry.WithError(err).Error("Failed to dispatch alert")
			}
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
				logrus.Printf("⚠️  Removing inactive agent %s (node: %s, pod: %s, last seen: %s ago)",
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
