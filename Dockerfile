# Build stage
FROM golang:1.24 AS builder

WORKDIR /app

# Install protoc and required tools
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Install protoc-gen-go and protoc-gen-go-grpc
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Generate protobuf files
RUN protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    pkg/api/proto/telemetry.proto

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /rasp-controller ./cmd/server

# Final stage
FROM ubuntu:22.04

WORKDIR /

# Install grpc-health-probe with noninteractive frontend
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    wget \
    && wget -qO/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v0.4.19/grpc_health_probe-linux-amd64 \
    && chmod +x /bin/grpc_health_probe \
    && apt-get remove -y wget \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /rasp-controller .

# Expose gRPC port
EXPOSE 50051

# Run the service
ENTRYPOINT ["/rasp-controller"]
