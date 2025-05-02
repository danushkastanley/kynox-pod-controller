package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	pb "pod-controller/pkg/telemetry"
	"google.golang.org/grpc/codes"
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
		return nil, status.Error(codes.InvalidArgument, "agent_id is required")
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
		return &pb.ConnectionStatus{
			Status:       pb.ConnectionStatus_ERROR,
			AgentId:     req.AgentId,
			ErrorMessage: "agent not registered",
		}, nil
	}

	if agent.SessionID != req.SessionId {
		s.mu.Unlock()
		return &pb.ConnectionStatus{
			Status:       pb.ConnectionStatus_ERROR,
			AgentId:     req.AgentId,
			ErrorMessage: "invalid session",
		}, nil
	}

	agent.LastSeen = time.Now()
	s.mu.Unlock()

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
				delete(s.agents, id)
			}
		}
		s.mu.Unlock()
	}
}

func generateSessionID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
