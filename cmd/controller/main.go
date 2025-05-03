package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"pod-controller/pkg/health"
	"pod-controller/pkg/server"
	pb "pod-controller/pkg/telemetry"

	"github.com/sirupsen/logrus"
)

func main() {
	// Get node name from Kubernetes downward API
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		// Fallback to hostname if not in K8s
		var err error
		nodeName, err = os.Hostname()
		if err != nil {
			logrus.Fatalf("Failed to get hostname: %v", err)
		}
	}

	// Get pod name from Kubernetes downward API
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		// Generate a unique name for local development
		podName = fmt.Sprintf("controller-%d", time.Now().Unix())
	}

	// Set up logging
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel != "" {
		level, err := logrus.ParseLevel(logLevel)
		if err != nil {
			logrus.Warnf("Invalid log level %q, defaulting to info", logLevel)
			logrus.SetLevel(logrus.InfoLevel)
		} else {
			logrus.SetLevel(level)
		}
	}

	logrus.WithFields(logrus.Fields{
		"node": nodeName,
		"pod":  podName,
	}).Info("Starting RASP controller")

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
	telemetryServer := server.NewTelemetryServer(5 * time.Minute) // 5 minute timeout for inactive agents
	pb.RegisterTelemetryServiceServer(grpcServer, telemetryServer)

	// Create and register health server
	healthServer := health.NewHealthServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	// Enable reflection for debugging
	reflection.Register(grpcServer)

	// Start server in a goroutine
	go func() {
		log.Printf("Starting gRPC server on port %s", port)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Start cleanup goroutine
	go telemetryServer.CleanupInactiveAgents()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down gRPC server...")
	grpcServer.GracefulStop()
	log.Println("Server stopped")
}
