package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	pb "pod-controller/pkg/telemetry"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	AgentIDMetadataKey         = "x-agent-id"
	SessionIDMetadataKey       = "x-session-id"
	defaultMaxConnectedAgents  = 10_000
	maxAgentIDBytes            = 128
	maxKubernetesIdentityBytes = 253
	sessionIDBytes             = 32
	encodedSessionIDBytes      = sessionIDBytes * 2
)

func (s *TelemetryServer) ConnectAgent(ctx context.Context, req *pb.ConnectRequest) (*pb.ConnectResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "connect request is required")
	}
	if err := validateIdentity("agent_id", req.AgentId, maxAgentIDBytes, true); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := validateIdentity("node_name", req.NodeName, maxKubernetesIdentityBytes, false); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := validateIdentity("pod_name", req.PodName, maxKubernetesIdentityBytes, false); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create agent session")
	}

	agent := &ConnectedAgent{
		AgentID:   req.AgentId,
		NodeName:  req.NodeName,
		PodName:   req.PodName,
		SessionID: sessionID,
		LastSeen:  time.Now(),
		Metadata:  make(map[string]string),
	}

	s.mu.Lock()
	existing, reconnecting := s.agents[req.AgentId]
	if reconnecting {
		metadataAgentID, metadataSessionID, metadataErr := agentSessionFromMetadata(ctx)
		if metadataErr != nil || metadataAgentID != req.AgentId || !sessionIDsEqual(existing.SessionID, metadataSessionID) {
			s.mu.Unlock()
			return nil, status.Error(codes.PermissionDenied, "valid agent session metadata is required to reconnect")
		}
	} else if len(s.agents) >= s.agentLimit() {
		s.mu.Unlock()
		return nil, status.Error(codes.ResourceExhausted, "maximum connected agents reached")
	}
	s.agents[req.AgentId] = agent
	s.mu.Unlock()

	if reconnecting {
		logrus.Info("Agent reconnected")
	} else {
		logrus.Info("Agent connected")
		if s.promMetrics != nil {
			s.promMetrics.RecordAgentConnect(req.NodeName)
		}
	}

	return &pb.ConnectResponse{Success: true, SessionId: sessionID}, nil
}

func (s *TelemetryServer) SendHeartbeat(_ context.Context, req *pb.Heartbeat) (*pb.ConnectionStatus, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "heartbeat is required")
	}
	if err := validateIdentity("agent_id", req.AgentId, maxAgentIDBytes, true); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := validateSessionID(req.SessionId); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	s.mu.Lock()
	agent, exists := s.agents[req.AgentId]
	if !exists {
		s.mu.Unlock()
		return &pb.ConnectionStatus{
			Status:       pb.ConnectionStatus_ERROR,
			AgentId:      req.AgentId,
			ErrorMessage: "agent not registered",
		}, nil
	}
	if !sessionIDsEqual(agent.SessionID, req.SessionId) {
		s.mu.Unlock()
		return &pb.ConnectionStatus{
			Status:       pb.ConnectionStatus_ERROR,
			AgentId:      req.AgentId,
			ErrorMessage: "invalid session",
		}, nil
	}

	lastSeen := agent.LastSeen
	agent.LastSeen = time.Now()
	s.mu.Unlock()

	if time.Since(lastSeen) > 30*time.Second {
		logrus.Debug("Agent heartbeat received")
	}
	if s.promMetrics != nil {
		s.promMetrics.RecordHeartbeat(agent.AgentID, agent.NodeName)
	}

	return &pb.ConnectionStatus{Status: pb.ConnectionStatus_CONNECTED, AgentId: req.AgentId}, nil
}

func (s *TelemetryServer) StreamEvents(stream pb.TelemetryService_StreamEventsServer) error {
	agentID, sessionID, err := agentSessionFromMetadata(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	if _, ok := s.activeAgent(agentID, sessionID); !ok {
		return status.Error(codes.PermissionDenied, "agent session is not active")
	}

	logrus.Info("Agent event stream started")
	for {
		event, recvErr := stream.Recv()
		if recvErr != nil {
			if recvErr == io.EOF {
				logrus.Info("Agent event stream closed")
				return nil
			}
			return recvErr
		}

		agent, ok := s.activeAgent(agentID, sessionID)
		if !ok {
			return status.Error(codes.PermissionDenied, "agent session is no longer active")
		}
		bindEventToAgent(event, agentID)

		if processErr := s.processEvent(event, agent); processErr != nil {
			logrus.WithError(processErr).Error("Failed to process event")
			if sendErr := stream.Send(&pb.EventResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to process event: %v", processErr),
			}); sendErr != nil {
				return sendErr
			}
			continue
		}

		if sendErr := stream.Send(&pb.EventResponse{
			Success: true,
			Message: "Event processed successfully",
		}); sendErr != nil {
			return sendErr
		}
	}
}

func (s *TelemetryServer) activeAgent(agentID, sessionID string) (*ConnectedAgent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agent, exists := s.agents[agentID]
	return agent, exists && sessionIDsEqual(agent.SessionID, sessionID)
}

func (s *TelemetryServer) agentLimit() int {
	if s.maxAgents > 0 {
		return s.maxAgents
	}
	return defaultMaxConnectedAgents
}

func bindEventToAgent(event *pb.SecurityEvent, agentID string) {
	if event.ContainerContext == nil {
		event.ContainerContext = make(map[string]string)
	}
	event.ContainerContext["agent_id"] = agentID
}

func agentSessionFromMetadata(ctx context.Context) (string, string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", "", fmt.Errorf("agent session metadata is required")
	}

	agentIDs := md.Get(AgentIDMetadataKey)
	sessionIDs := md.Get(SessionIDMetadataKey)
	if len(agentIDs) != 1 || len(sessionIDs) != 1 {
		return "", "", fmt.Errorf("exactly one agent and session metadata value is required")
	}
	if err := validateIdentity("agent_id", agentIDs[0], maxAgentIDBytes, true); err != nil {
		return "", "", err
	}
	if err := validateSessionID(sessionIDs[0]); err != nil {
		return "", "", err
	}
	return agentIDs[0], sessionIDs[0], nil
}

func validateIdentity(name, value string, maxBytes int, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, maxBytes)
	}
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is not a valid identity", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains control characters", name)
		}
	}
	return nil
}

func validateSessionID(sessionID string) error {
	if len(sessionID) != encodedSessionIDBytes {
		return fmt.Errorf("session_id is invalid")
	}
	if _, err := hex.DecodeString(sessionID); err != nil {
		return fmt.Errorf("session_id is invalid")
	}
	return nil
}

func generateSessionID() (string, error) {
	bytes := make([]byte, sessionIDBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random session: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func sessionIDsEqual(expected, actual string) bool {
	if len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}
