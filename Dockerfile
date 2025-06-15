# Build stage
FROM --platform=linux/amd64 golang:1.24-bullseye as builder

WORKDIR /app

# Copy only necessary files for building
COPY go.mod go.sum ./
COPY pkg/ pkg/
COPY cmd/ cmd/
COPY .env.example .env

# Install protoc, Go plugins, and grpc-health-probe
RUN apt-get update && apt-get install -y protobuf-compiler wget && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2 && \
    GRPC_HEALTH_PROBE_VERSION=v0.4.19 && \
    wget -qO/go/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
    chmod +x /go/bin/grpc_health_probe

# Generate protobuf code and update dependencies
RUN protoc --go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative pkg/telemetry/telemetry.proto && \
    go mod tidy

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/controller ./cmd/controller

# Create final image
FROM --platform=linux/amd64 gcr.io/distroless/static:nonroot

WORKDIR /app
COPY --from=builder /app/controller .
COPY --from=builder /go/bin/grpc_health_probe /usr/local/bin/grpc-health-probe
COPY --from=builder /app/.env .
COPY --from=builder /app/rules ./rules/

EXPOSE 50051
USER nonroot:nonroot

ENTRYPOINT ["/app/controller"]
