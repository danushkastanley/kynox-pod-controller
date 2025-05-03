# Pod Controller - Runtime Application Self-Protection (RASP)

A Kubernetes-native RASP controller that provides real-time security monitoring and threat detection for containerized applications using eBPF technology.

## Features

### Real-time Security Monitoring
- Process execution tracking
- Network activity monitoring
- File system operations
- Security-sensitive syscalls
- Container operations

### Advanced Threat Detection
- Privilege escalation attempts
- Suspicious command execution
- Container escape attempts
- Anomalous process behavior
- Unauthorized network connections
- Sensitive file access
- BPF/Seccomp operations

### Event Processing
- Real-time event streaming via gRPC
- Batch event processing
- Structured logging with context
- Container-aware monitoring
- Kubernetes metadata integration

### Architecture
- gRPC server for event reception
- Detection engine for threat analysis
- Policy engine for response actions
- Kubernetes-native deployment
- Health monitoring and metrics

## Requirements

### System Requirements
- Kubernetes cluster
- Linux kernel ≥ 5.8
- Go 1.21 or higher

### Dependencies
- gRPC/Protocol Buffers
- Logrus for structured logging
- Kubernetes client-go

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/pod-controller.git
cd pod-controller
```

2. Build the controller:
```bash
go mod tidy
go build -o bin/controller cmd/controller/main.go
```

3. Deploy to Kubernetes:
```bash
kubectl apply -f deployments/pod-controller-kubernetes.yaml
```

## Configuration

The controller can be configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | gRPC server port | 50051 |
| NODE_NAME | Kubernetes node name | - |
| POD_NAME | Controller pod name | - |

## Architecture

### Components
1. **gRPC Server**
   - Handles agent connections
   - Manages event streaming
   - Session management

2. **Threat Detection Engine**
   - Real-time event analysis
   - Pattern matching
   - Anomaly detection
   - Behavioral analysis

3. **Event Processor**
   - Event categorization
   - Context enrichment
   - Severity assessment
   - Alert generation

### Communication Flow
```
Pod Agent (Rust) → gRPC Stream → Controller → Event Processing → Alerts
```

## Monitored Events

### Process Operations
- EXEC (command execution)
- FORK (process creation)

### Network Operations
- CONNECT (outbound connections)
- BIND (listening ports)
- ACCEPT (inbound connections)
- SOCKET (socket creation)

### File Operations
- OPEN (file access)
- MOUNT/UMOUNT (filesystem operations)

### Security Operations
- SETUID/SETGID (privilege changes)
- PTRACE (process debugging)
- CAPSET (capability changes)
- BPF_PROG (eBPF operations)
- SECCOMP (syscall filtering)

## Alert Severity Levels

### CRITICAL
- Privilege escalation attempts
- BPF program loading
- Suspicious ptrace operations
- Suspicious mount operations

### WARNING
- Suspicious command execution
- External network connections
- Sensitive file access
- Anomalous process/network activity
- Seccomp modifications

## Development

### Building from Source
```bash
# Build the controller
make build

# Run tests
make test

# Generate protobuf code
make proto
```

### Adding New Detection Rules
1. Add detection logic in `pkg/server/threat_detection.go`
2. Update event processing in `pkg/server/server.go`
3. Add test cases in `pkg/server/threat_detection_test.go`

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
