package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	pb "github.com/danushkastanley/rasp-controller/pkg/telemetry"
)

// TelemetryServer implements the TelemetryService gRPC service
type TelemetryServer struct {
	pb.UnimplementedTelemetryServiceServer
	mu      sync.RWMutex
	streams map[string]pb.TelemetryService_StreamEventsServer
	ready   bool
}

// NewTelemetryServer creates a new telemetry server instance
func NewTelemetryServer() *TelemetryServer {
	return &TelemetryServer{
		streams: make(map[string]pb.TelemetryService_StreamEventsServer),
	}
}

// StreamEvents handles streaming security events from agents
func (s *TelemetryServer) StreamEvents(stream pb.TelemetryService_StreamEventsServer) error {
	log.Println("Agent connected to stream events")

	// Get agent ID from context or metadata
	agentID := fmt.Sprintf("agent-%d", len(s.streams)+1)

	// Register stream
	s.mu.Lock()
	s.streams[agentID] = stream
	if !s.ready {
		s.ready = true
	}
	s.mu.Unlock()

	// Cleanup on exit
	defer func() {
		s.mu.Lock()
		delete(s.streams, agentID)
		if len(s.streams) == 0 {
			s.ready = false
		}
		s.mu.Unlock()
	}()

	// Send initial configuration
	config := &pb.TelemetryConfig{
		EnableExecEvents:       true,
		EnableFileEvents:       true,
		EnableNetworkEvents:    true,
		EnablePrivilegeEvents:  true,
		EnableMountEvents:      true,
		EnableCapabilityEvents: true,
		EnableBpfEvents:        true,
		EnableSeccompEvents:    true,
		FilterRules:            "",
		BatchSize:              100,
		BatchIntervalMs:        1000,
	}

	if err := stream.Send(config); err != nil {
		log.Printf("Error sending config: %v", err)
		return err
	}

	// Process incoming events
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			log.Printf("Agent %s disconnected", agentID)
			return nil
		}
		if err != nil {
			log.Printf("Error receiving from agent %s: %v", agentID, err)
			return status.Errorf(codes.Unknown, "failed to receive event: %v", err)
		}

		// Print event details
		eventJSON, _ := json.MarshalIndent(event, "", "  ")
		log.Printf("Received event from agent %s: %s", agentID, string(eventJSON))
	}
}

// SendEventBatch handles batched security events from agents
func (s *TelemetryServer) SendEventBatch(ctx context.Context, batch *pb.SecurityEventBatch) (*pb.TelemetryConfig, error) {
	log.Printf("Received batch of %d events", len(batch.Events))

	// Process each event in the batch
	for i, event := range batch.Events {
		log.Printf("Event %d: Type=%d, PID=%d, Command=%s", 
			i, event.EventType, event.Pid, event.Command)
		
		// Print container context if available
		if event.ContainerId != nil && *event.ContainerId != "" {
			log.Printf("  Container: %s, Pod: %s, Namespace: %s", 
				*event.ContainerId, *event.PodName, *event.Namespace)
		}

		// Print event-specific details based on the event type
		switch event.EventType {
		case 1: // EXEC
			if exec := event.GetExec(); exec != nil {
				log.Printf("  Exec: %s %v", exec.Filename, exec.Args)
			}
		case 2: // OPEN
			if file := event.GetFile(); file != nil {
				log.Printf("  File: %s", file.Path)
			}
		case 3: // CONNECT
			if network := event.GetNetwork(); network != nil {
				log.Printf("  Network: %s:%d -> %s:%d", 
					network.SourceIp, network.SourcePort,
					network.DestinationIp, network.DestinationPort)
			}
		case 6: // SETUID
			if priv := event.GetPrivilege(); priv != nil {
				log.Printf("  Privilege: UID %d -> %d", priv.OldUid, priv.NewUid)
			}
		}
	}

	// Return updated configuration
	return &pb.TelemetryConfig{
		EnableExecEvents:       true,
		EnableFileEvents:       true,
		EnableNetworkEvents:    true,
		EnablePrivilegeEvents:  true,
		EnableMountEvents:      true,
		EnableCapabilityEvents: true,
		EnableBpfEvents:        true,
		EnableSeccompEvents:    true,
		FilterRules:            "",
		BatchSize:              100,
		BatchIntervalMs:        1000,
	}, nil
}

func main() {
	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "50051"
	}

	// Create listener
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create and register telemetry server
	telemetryServer := NewTelemetryServer()
	pb.RegisterTelemetryServiceServer(grpcServer, telemetryServer)
	
	// Create health server
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	// Start health check goroutine
	go func() {
		for {
			telemetryServer.mu.RLock()
			ready := telemetryServer.ready
			telemetryServer.mu.RUnlock()

			if ready {
				healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
			} else {
				healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
			}

			// Check every second
			time.Sleep(time.Second)
		}
	}()
	
	// Enable reflection for debugging
	reflection.Register(grpcServer)

	// Start server in a goroutine
	go func() {
		log.Printf("Starting gRPC server on port %s", port)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down gRPC server...")
	grpcServer.GracefulStop()
	log.Println("Server stopped")
}
