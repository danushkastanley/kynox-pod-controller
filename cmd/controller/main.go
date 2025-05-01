package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	pb "github.com/danushkastanley/rasp-controller/pkg/api/proto"
	health_internal "github.com/danushkastanley/rasp-controller/internal/health"
	telemetry_internal "github.com/danushkastanley/rasp-controller/internal/telemetry"
)

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

	// Create and register telemetry server using internal package
	telemetryServer := telemetry_internal.NewServer()
	pb.RegisterTelemetryServiceServer(grpcServer, telemetryServer)

	// Create and register health server using internal package
	healthServer := &health_internal.Server{} // Instantiate the server struct
	healthpb.RegisterHealthServer(grpcServer, healthServer)

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
