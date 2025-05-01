# Build stage
FROM golang:1.24-bullseye as builder

WORKDIR /app

# Copy everything
COPY . .

# Install protobuf compiler and grpc-health-probe
RUN apt-get update && apt-get install -y protobuf-compiler && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2 && \
    GOBIN=/tmp go install github.com/grpc-ecosystem/grpc-health-probe@latest

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
COPY --from=builder /tmp/grpc-health-probe /bin/grpc-health-probe

# Set environment variables
ENV PORT=50051

# Expose the gRPC port
EXPOSE 50051

# Run the controller
ENTRYPOINT ["/app/controller"]
