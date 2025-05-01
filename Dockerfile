# Build stage
FROM --platform=linux/amd64 golang:1.24-bullseye as builder

WORKDIR /app

# Copy only necessary files for building
COPY go.mod go.sum ./
COPY pkg/ pkg/
COPY cmd/ cmd/

# Install protoc and Go plugins
RUN apt-get update && apt-get install -y protobuf-compiler && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2

# Generate protobuf code and update dependencies
RUN protoc --go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative pkg/telemetry/telemetry.proto && \
    go mod tidy

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/controller ./cmd/controller

# Create final image
FROM --platform=linux/amd64 gcr.io/distroless/static:nonroot

WORKDIR /app
COPY --from=builder /app/controller .

EXPOSE 50051
USER nonroot:nonroot

ENTRYPOINT ["/app/controller"]
