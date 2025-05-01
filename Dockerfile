# Build stage
FROM golang:1.24-bullseye as builder

WORKDIR /app

# Copy everything
COPY . .

# Install dependencies and grpc-health-probe
RUN apt-get update && apt-get install -y protobuf-compiler curl && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2 && \
    # Download pre-compiled grpc-health-probe
    curl -Lo /tmp/grpc-health-probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v0.4.37/grpc-health-probe-linux-amd64 && \
    chmod +x /tmp/grpc-health-probe && \
    echo "--- Checking for health probe in /tmp ---" && \
    ls -l /tmp

# Generate protobuf code and update dependencies
RUN protoc --go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative pkg/api/proto/telemetry.proto && \
    go mod tidy

# Build the controller
ENV GO111MODULE=on
ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0

RUN go build -o /app/controller ./cmd/controller

# Create a smaller runtime image
FROM debian:bullseye-slim

WORKDIR /app

# Copy the compiled binary and health probe
COPY --from=builder /app/controller /app/controller
COPY --from=builder /tmp/grpc-health-probe /usr/local/bin/grpc-health-probe

# Set environment variables
ENV PORT=50051

# Expose the gRPC port
EXPOSE 50051

# Run the controller
ENTRYPOINT ["/app/controller"]
