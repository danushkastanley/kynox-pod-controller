package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	pb "github.com/danushkastanley/rasp-controller/pkg/api/proto"
	"github.com/danushkastanley/rasp-controller/internal/health"
	"github.com/danushkastanley/rasp-controller/internal/telemetry"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

func main() {
	flag.Parse()

	// Create listener
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// Create gRPC server
	s := grpc.NewServer()

	// Create and register telemetry server
	telemetryServer := telemetry.NewServer()
	pb.RegisterTelemetryServiceServer(s, telemetryServer)

	// Create and register health server
	healthServer := &health.Server{}
	grpc_health_v1.RegisterHealthServer(s, healthServer)

	// Register reflection service for debugging
	reflection.Register(s)

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down gRPC server...")
		s.GracefulStop()
	}()

	// Start server
	log.Printf("RASP Controller starting on port %d...", *port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
