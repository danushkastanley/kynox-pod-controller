package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"pod-controller/pkg/alert"
	"pod-controller/pkg/classifier"
	pb "pod-controller/pkg/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"golang.org/x/time/rate"
)

type ConnectedAgent struct {
	AgentID   string
	NodeName  string
	PodName   string
	SessionID string
	LastSeen  time.Time
	Metadata  map[string]string
}

type AlertKey struct {
	EventType    string
	Command      string
	Namespace    string
	PodName      string
	ContainerID  string
	Severity     string
}

type AlertAggregation struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
	Message   string
}

type TelemetryServer struct {
	pb.UnimplementedTelemetryServiceServer
	agents        map[string]*ConnectedAgent
	mu           sync.RWMutex
	classifier    *classifier.EventClassifier
	alertLimiter  *rate.Limiter
	alerter       *alert.AlertDispatcher
	// Metrics
	eventCounts   map[string]int64
	severityCounts map[string]int64
	// Alert aggregation
	alertAggregation map[AlertKey]*AlertAggregation
	aggregationMu   sync.RWMutex
	metricsMu      sync.RWMutex
	timeout        time.Duration
}

func NewTelemetryServer(timeout time.Duration) *TelemetryServer {
	// Initialize alert dispatcher
	alertDispatcher, err := alert.NewAlertDispatcher()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create alert dispatcher")
	}

	return &TelemetryServer{
		agents:          make(map[string]*ConnectedAgent),
		classifier:      classifier.NewEventClassifier(),
		alertLimiter:    rate.NewLimiter(rate.Every(1*time.Second), 1),
		alerter:         alertDispatcher,
		eventCounts:     make(map[string]int64),
		severityCounts:  make(map[string]int64),
		alertAggregation: make(map[AlertKey]*AlertAggregation),
		timeout:         timeout,
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
	agentID := event.GetContainerContext()["agent_id"]
	agent, exists := s.agents[agentID]
	s.mu.RUnlock()

	if !exists {
		return status.Error(codes.FailedPrecondition, "agent not connected")
	}

	logrus.Printf("🔄 Started event stream for agent %s (node: %s, pod: %s)", 
		agent.AgentID, agent.NodeName, agent.PodName)

	// Process the first event
	if err := s.processEvent(event, agent); err != nil {
		logrus.WithError(err).Error("Failed to process event")
		return err
	}

	// Send acknowledgment for first event
	if err := stream.Send(&pb.EventResponse{
		Success: true,
		Message: "Event processed successfully",
	}); err != nil {
		logrus.WithError(err).Error("Failed to send acknowledgment")
		return err
	}

	// Process subsequent events
	for {
		event, err := stream.Recv()
		if err != nil {
			return err
		}

		if err := s.processEvent(event, agent); err != nil {
			logrus.WithError(err).Error("Failed to process event")
			continue
		}

		// Send acknowledgment
		if err := stream.Send(&pb.EventResponse{
			Success: true,
			Message: "Event processed successfully",
		}); err != nil {
			logrus.WithError(err).Error("Failed to send acknowledgment")
			return err
		}
	}
}

func (s *TelemetryServer) updateMetrics(eventType string, severity classifier.Severity) {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	
	s.eventCounts[eventType]++
	s.severityCounts[string(severity)]++
}

func (s *TelemetryServer) GetMetrics() map[string]interface{} {
	s.metricsMu.RLock()
	defer s.metricsMu.RUnlock()
	
	return map[string]interface{}{
		"event_counts":    s.eventCounts,
		"severity_counts": s.severityCounts,
	}
}

func (s *TelemetryServer) aggregateAlert(key AlertKey, message string) bool {
	now := time.Now()
	s.aggregationMu.Lock()
	defer s.aggregationMu.Unlock()

	// Check if we have an existing aggregation
	if agg, exists := s.alertAggregation[key]; exists {
		// If last alert was more than 5 minutes ago, create new aggregation
		if now.Sub(agg.LastSeen) > 5*time.Minute {
			s.alertAggregation[key] = &AlertAggregation{
				Count:     1,
				FirstSeen: now,
				LastSeen:  now,
				Message:   message,
			}
			return true
		}

		// Update existing aggregation
		agg.Count++
		agg.LastSeen = now
		
		// Send aggregated alert every 10 events or every minute
		if agg.Count%10 == 0 || now.Sub(agg.LastSeen) >= time.Minute {
			return true
		}
		return false
	}

	// Create new aggregation
	s.alertAggregation[key] = &AlertAggregation{
		Count:     1,
		FirstSeen: now,
		LastSeen:  now,
		Message:   message,
	}
	return true
}

func (s *TelemetryServer) processEvent(event *pb.SecurityEvent, agent *ConnectedAgent) error {
	// Extract container context
	containerContext := event.GetContainerContext()
	containerId := containerContext["container_id"]
	namespace := containerContext["namespace"]
	podName := containerContext["pod_name"]

	// Initialize fields for logging
	fields := logrus.Fields{
		"agent_id":     agent.AgentID,
		"node":         agent.NodeName,
		"pod":          agent.PodName,
		"container_id": containerId,
		"namespace":    namespace,
		"event_type":   event.GetEventType().String(),
	}

	// Classify the event
	severity, message := s.classifier.ClassifyEvent(event)

	// Update metrics
	s.updateMetrics(event.GetEventType().String(), severity)

	// Log all events at appropriate level
	switch severity {
	case classifier.SeverityCritical:
		logrus.WithFields(fields).Error(message)
	case classifier.SeverityHigh:
		logrus.WithFields(fields).Warn(message)
	case classifier.SeverityWarn:
		logrus.WithFields(fields).Info(message)
	default:
		logrus.WithFields(fields).Debug(message)
	}

	// Only process HIGH and CRITICAL events
	if severity == classifier.SeverityHigh || severity == classifier.SeverityCritical {
		// Check rate limit before sending alert
		if !s.alertLimiter.Allow() {
			logrus.WithFields(fields).Warn("Alert rate limited, skipping notification")
			return nil
		}

		// Create alert key for aggregation
		alertKey := AlertKey{
			EventType:   event.GetEventType().String(),
			Command:     event.GetCommand(),
			Namespace:   namespace,
			PodName:    podName,
			ContainerID: containerId,
			Severity:    string(severity),
		}

		// Check if we should send alert based on aggregation
		shouldAlert := s.aggregateAlert(alertKey, message)
		if !shouldAlert {
			return nil
		}

		// Get aggregation info
		s.aggregationMu.RLock()
		agg := s.alertAggregation[alertKey]
		s.aggregationMu.RUnlock()

		// Create alert context with aggregation info
		alertContext := map[string]string{
			"agent_id":     agent.AgentID,
			"node_name":    agent.NodeName,
			"pod_name":     agent.PodName,
			"container_id": containerId,
			"namespace":    namespace,
			"event_type":   event.GetEventType().String(),
			"command":      event.GetCommand(),
			"severity":     string(severity),
			"count":        fmt.Sprintf("%d", agg.Count),
			"first_seen":   agg.FirstSeen.Format(time.RFC3339),
			"duration":     time.Since(agg.FirstSeen).String(),
		}

		// Create and dispatch alert
		alertLevel := alert.AlertLevel(s.getAlertLevel(severity))
		alert := alert.CreateAlert(
			alertLevel,
			fmt.Sprintf("%s: %s", severity, message),
			fmt.Sprintf("Security event detected in pod %s/%s on node %s", namespace, podName, agent.NodeName),
			alertContext,
		)

		if err := s.alerter.Dispatch(alert); err != nil {
			logrus.WithError(err).Error("Failed to send alert")
			return err
		}
	}

	return nil
}

func (s *TelemetryServer) getAlertLevel(severity classifier.Severity) string {
	switch severity {
	case classifier.SeverityCritical:
		return "CRITICAL"
	case classifier.SeverityHigh:
		return "HIGH"
	case classifier.SeverityWarn:
		return "WARN"
	default:
		return "INFO"
	}
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
