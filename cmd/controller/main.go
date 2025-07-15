package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
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

	// Get ports from environment or use defaults
	grpcPort := os.Getenv("PORT")
	if grpcPort == "" {
		grpcPort = "50051"
	}

	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8080"
	}

	// Create gRPC listener
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", grpcPort))
	if err != nil {
		log.Fatalf("Failed to listen on gRPC port %s: %v", grpcPort, err)
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

	// Create HTTP server for metrics API
	httpMux := http.NewServeMux()

	// Create classifier API and register routes
	classifierAPI := server.NewClassifierAPI(telemetryServer)
	classifierAPI.RegisterRoutes(httpMux)

	// Add health check endpoint for HTTP server
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "healthy", "service": "rasp-controller"}`))
	})

	// Add metrics endpoint for Prometheus scraping
	httpMux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		// Redirect to classifier metrics for now
		http.Redirect(w, r, "/api/v1/classifier/metrics/summary", http.StatusTemporaryRedirect)
	})

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%s", httpPort),
		Handler: httpMux,
	}

	// Start gRPC server in a goroutine
	go func() {
		logrus.WithField("port", grpcPort).Info("Starting gRPC server")
		if err := grpcServer.Serve(lis); err != nil {
			logrus.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	// Start HTTP server in a goroutine
	go func() {
		logrus.WithField("port", httpPort).Info("Starting HTTP metrics server")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("Failed to serve HTTP: %v", err)
		}
	}()

	// Start cleanup goroutine
	go telemetryServer.CleanupInactiveAgents()

	logrus.Info("RASP Controller started successfully")
	logrus.WithFields(logrus.Fields{
		"grpc_port": grpcPort,
		"http_port": httpPort,
	}).Info("Server endpoints ready")

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logrus.Info("Shutting down servers...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server gracefully
	if err := httpServer.Shutdown(ctx); err != nil {
		logrus.WithError(err).Error("HTTP server shutdown error")
	}

	// Shutdown gRPC server gracefully
	grpcServer.GracefulStop()

	logrus.Info("Servers stopped successfully")
}
