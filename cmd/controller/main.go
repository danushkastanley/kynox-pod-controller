package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"pod-controller/pkg/health"
	"pod-controller/pkg/metrics"
	"pod-controller/pkg/server"
	pb "pod-controller/pkg/telemetry"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const (
	defaultMTLSCACertFile     = "/etc/rasp/tls/ca/ca.crt"
	defaultMTLSServerCertFile = "/etc/rasp/tls/server/tls.crt"
	defaultMTLSServerKeyFile  = "/etc/rasp/tls/server/tls.key"
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
	grpcOptions, err := buildGRPCServerOptions()
	if err != nil {
		logrus.Fatalf("Failed to configure gRPC transport security: %v", err)
	}
	grpcServer := grpc.NewServer(grpcOptions...)

	// Initialize Prometheus metrics
	promMetrics := metrics.NewMetrics()
	promMetrics.SetStartTime(float64(time.Now().Unix()))

	// Create and register telemetry server with metrics
	telemetryServer := server.NewTelemetryServerWithMetrics(5*time.Minute, promMetrics) // 5 minute timeout for inactive agents
	pb.RegisterTelemetryServiceServer(grpcServer, telemetryServer)

	// Create and register health server
	healthServer := health.NewHealthServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	if envEnabled("GRPC_REFLECTION_ENABLED") {
		reflection.Register(grpcServer)
		logrus.Info("gRPC reflection enabled")
	}

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

	// Add Prometheus metrics endpoint
	httpMux.Handle("/metrics", promhttp.Handler())

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%s", httpPort),
		Handler:           httpMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
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

	// Start uptime metrics updater
	go func() {
		startTime := time.Now()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			promMetrics.SetUptime(time.Since(startTime).Seconds())
		}
	}()

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

func buildGRPCServerOptions() ([]grpc.ServerOption, error) {
	if os.Getenv("MTLS_ENABLED") == "false" {
		logrus.Warn("mTLS is disabled for the gRPC server; use only for local development")
		return nil, nil
	}

	tlsConfig, err := loadServerTLSConfig()
	if err != nil {
		return nil, err
	}

	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}, nil
}

func loadServerTLSConfig() (*tls.Config, error) {
	caCertFile := getEnvWithDefault("MTLS_CA_CERT_FILE", defaultMTLSCACertFile)
	serverCertFile := getEnvWithDefault("MTLS_SERVER_CERT_FILE", defaultMTLSServerCertFile)
	serverKeyFile := getEnvWithDefault("MTLS_SERVER_KEY_FILE", defaultMTLSServerKeyFile)

	serverCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate and key: %w", err)
	}

	caPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA certificate: %w", err)
	}

	clientCAs := x509.NewCertPool()
	if ok := clientCAs.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("client CA certificate file %q did not contain a valid PEM certificate", caCertFile)
	}

	logrus.WithFields(logrus.Fields{
		"ca_cert_file":     caCertFile,
		"server_cert_file": serverCertFile,
	}).Info("mTLS enabled for gRPC server; client certificates are required")

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func envEnabled(key string) bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(key)), "true")
}
