package health

import (
	"context"

	"google.golang.org/grpc/health/grpc_health_v1"
)

// HealthServer implements the gRPC health check service
type HealthServer struct {
	grpc_health_v1.UnimplementedHealthServer
}

// NewHealthServer creates a new health check server
func NewHealthServer() *HealthServer {
	return &HealthServer{}
}

// Check implements the health check RPC
func (s *HealthServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	}, nil
}

// Watch implements the streaming health check RPC
func (s *HealthServer) Watch(req *grpc_health_v1.HealthCheckRequest, stream grpc_health_v1.Health_WatchServer) error {
	// Send a single response indicating the service is serving
	return stream.Send(&grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	})
}
