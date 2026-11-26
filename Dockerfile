# Build stage runs natively and cross-compiles for the requested platform.
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

# Copy only necessary files for building
COPY go.mod go.sum ./
COPY pkg/ pkg/
COPY cmd/ cmd/
COPY rules/ rules/

# Build the application
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -mod=readonly -o /app/controller ./cmd/controller

# Create final image
FROM gcr.io/distroless/static:nonroot

WORKDIR /app
COPY --from=builder /app/controller .
COPY --from=builder /app/rules ./rules/

EXPOSE 50051
# Numeric UID/GID (distroless "nonroot") so kubelet can enforce runAsNonRoot.
USER 65532:65532

ENTRYPOINT ["/app/controller"]
