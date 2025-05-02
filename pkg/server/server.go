package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

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
	mu      sync.RWMutex
	agents  map[string]*ConnectedAgent // key: agent_id
	timeout time.Duration // timeout for inactive agents
}

func NewTelemetryServer(timeout time.Duration) *TelemetryServer {
	return &TelemetryServer{
		agents:  make(map[string]*ConnectedAgent),
		timeout: timeout,
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
	// Process the security event
	// Add your event processing logic here
	return nil
}

// CleanupInactiveAgents starts a goroutine that periodically removes inactive agents
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
