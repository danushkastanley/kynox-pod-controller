package telemetry

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"

	pb "github.com/danushkastanley/rasp-controller/pkg/api/proto"
	"github.com/danushkastanley/rasp-controller/internal/detection"
	"github.com/danushkastanley/rasp-controller/internal/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the TelemetryService gRPC server
type Server struct {
	pb.UnimplementedTelemetryServiceServer
	detector *detection.Engine
	policy   *policy.Engine
	mu       sync.RWMutex
	streams  map[string]pb.TelemetryService_StreamEventsServer
}

// NewServer creates a new telemetry server instance
func NewServer() *Server {
	return &Server{
		detector: detection.NewEngine(),
		policy:   policy.NewEngine(),
		streams:  make(map[string]pb.TelemetryService_StreamEventsServer),
	}
}

// StreamEvents handles the bidirectional streaming of security events
func (s *Server) StreamEvents(stream pb.TelemetryService_StreamEventsServer) error {
	// Get agent ID from metadata or generate one
	ctx := stream.Context()
	agentID := getAgentID(ctx)

	// Register stream
	s.mu.Lock()
	s.streams[agentID] = stream
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.streams, agentID)
		s.mu.Unlock()
	}()

	for {
		event, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			// Log the specific error before returning
			log.Printf("ERROR receiving event from agent %s: %v", agentID, err)
			return status.Errorf(codes.Unknown, "failed to receive event: %v", err)
		}

		// Process the event
		if err := s.handleEvent(ctx, event); err != nil {
			log.Printf("Error handling event from agent %s: %v", agentID, err)
			continue
		}

		// Note: Config updates should be sent only when there are actual changes
		// Not after every event as it can overwhelm the agent
	}
}

// SendEventBatch handles batch event submissions
func (s *Server) SendEventBatch(ctx context.Context, batch *pb.SecurityEventBatch) (*pb.BatchResponse, error) {
	if len(batch.Events) == 0 {
		return &pb.BatchResponse{
			Success: true,
			Message: "Empty batch received",
		}, nil
	}

	for _, event := range batch.Events {
		if err := s.handleEvent(ctx, event); err != nil {
			return &pb.BatchResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to process event: %v", err),
			}, nil
		}
	}

	return &pb.BatchResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully processed %d events", len(batch.Events)),
	}, nil
}

// handleEvent processes a single security event
func (s *Server) handleEvent(ctx context.Context, event *pb.SecurityEvent) error {
	// Run event through detection engine
	threatLevel := s.detector.Analyze(event)

	// Apply policy rules
	action := s.policy.Evaluate(event, threatLevel)

	// Log the event with threat level
	logEvent(event, threatLevel, action)

	return nil
}

// sendConfigUpdate sends configuration updates to the agent
func (s *Server) sendConfigUpdate(stream pb.TelemetryService_StreamEventsServer) error {
	update := &pb.ConfigUpdate{
		Filter: &pb.EventFilter{
			IncludedTypes:    []pb.EventType{pb.EventType_EXEC, pb.EventType_SETUID},
			CommandPatterns:  []string{"nc", "bash", "curl"},
			UidList:         []uint32{0},
			CaptureAll:      false,
		},
		DebugMode: false,
	}

	return stream.Send(update)
}

// getAgentID extracts the agent ID from the context or generates a new one
func getAgentID(ctx context.Context) string {
	// TODO: Implement proper agent identification
	return "agent-default"
}

// logEvent logs the security event with its threat assessment
func logEvent(event *pb.SecurityEvent, threatLevel detection.ThreatLevel, action policy.Action) {
	log.Printf("[%s] Event Type: %s, Process: %s, UID: %d, Threat: %s, Action: %s",
		threatLevel,
		event.EventType,
		event.Process.GetCommand(),
		event.Process.GetUid(),
		threatLevel,
		action,
	)
}
