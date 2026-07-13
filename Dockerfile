# Build stage
FROM golang:1.25-bookworm AS builder

WORKDIR /app

# Copy only necessary files for building
COPY go.mod go.sum ./
COPY pkg/ pkg/
COPY cmd/ cmd/
COPY rules/ rules/

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -o /app/controller ./cmd/controller

# Create final image
FROM gcr.io/distroless/static:nonroot

WORKDIR /app
COPY --from=builder /app/controller .
COPY --from=builder /app/rules ./rules/

EXPOSE 50051
USER nonroot:nonroot

ENTRYPOINT ["/app/controller"]
