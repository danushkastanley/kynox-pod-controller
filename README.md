# Pod-Controller: RASP Security Controller for Kubernetes

A Kubernetes-native Runtime Application Self-Protection (RASP) controller that provides real-time security monitoring, threat detection, and incident response for containerized applications. The controller processes security events from eBPF-based agents and provides intelligent threat analysis with configurable alerting.

## FEATURES

### Real-time Security Event Processing
- **Stream Processing**: High-throughput gRPC event streaming from distributed agents
- **Event Correlation**: Correlates events across containers, pods, and nodes
- **Session Management**: Robust agent connection management with health monitoring
- **Scalable Architecture**: Handles thousands of concurrent agent connections

### Advanced Threat Detection Engine
- **Privilege Escalation Detection**: Identifies suspicious `setuid`/`setgid` and capability changes
- **Process Behavior Analysis**: Detects suspicious command execution patterns
- **Container Escape Attempts**: Monitors mount operations and namespace changes
- **Injection Attacks**: Identifies potential code injection via `ptrace` operations
- **Network Anomaly Detection**: Detects suspicious network connections and port usage
- **File System Monitoring**: Tracks sensitive file access and permission changes

### Intelligent Event Classification
- **Multi-level Severity Assessment**: INFO, WARNING, HIGH, CRITICAL threat levels
- **Context-aware Analysis**: Considers container runtime, privileges, and process trust levels
- **False Positive Reduction**: Filters legitimate system operations and trusted processes
- **Behavioral Pattern Matching**: Identifies attack patterns and techniques

### Comprehensive Alerting System
- **Multi-channel Notifications**: Slack, webhook, and email integration
- **Alert Aggregation**: Reduces noise through intelligent event grouping
- **Rate Limiting**: Prevents alert flooding with configurable thresholds
- **Rich Context**: Detailed process, network, and container information in alerts

### Kubernetes-native Integration
- **Service Discovery**: Automatic agent discovery and registration
- **Metadata Enrichment**: Integrates with Kubernetes API for pod/namespace context
- **ConfigMap Configuration**: Cloud-native configuration management
- **Health Monitoring**: Comprehensive health checks and observability

## ARCHITECTURE

```
pod-controller/
├── cmd/controller/              # Main application entry point
│   └── main.go                 # Server initialization and startup
├── pkg/                        # Core packages
│   ├── telemetry/              # gRPC protocol definitions
│   │   ├── telemetry.proto     # Service and message definitions
│   │   └── telemetry.pb.go     # Generated protobuf code
│   ├── server/                 # Core server implementation
│   │   ├── server.go           # Main gRPC server and event processing
│   │   └── threat_detection.go # Threat detection engine
│   ├── classifier/             # Event classification system
│   │   └── classifier.go       # Security event analysis and scoring
│   ├── alert/                  # Alert management system
│   │   ├── types.go            # Alert data structures
│   │   ├── dispatcher.go       # Alert routing and delivery
│   │   ├── config.go           # Alert configuration management
│   │   ├── slack.go            # Slack integration
│   │   └── webhook.go          # Generic webhook support
│   └── health/                 # Health check implementation
│       └── health.go           # gRPC health service
├── deployments/                # Kubernetes deployment manifests
│   ├── pod-controller-kubernetes.yaml  # Main deployment
│   └── pod-controller-config.yaml     # Configuration ConfigMap
├── Dockerfile                  # Multi-stage container build
├── go.mod                     # Go module dependencies
└── redeploy_pod_controller.sh # Development deployment script
```

### Core Components

#### gRPC Server (`pkg/server/`)
- **Connection Management**: Handles agent registration, authentication, and session management
- **Event Processing**: Processes high-volume security event streams
- **Threat Analysis**: Real-time threat detection and classification
- **Alert Generation**: Creates and dispatches security alerts

#### Threat Detection Engine (`pkg/server/threat_detection.go`)
- **Pattern Recognition**: Identifies known attack patterns and suspicious behaviors
- **Risk Assessment**: Evaluates threat severity based on context and behavior
- **Anomaly Detection**: Detects deviations from normal container behavior
- **Process Trust Evaluation**: Maintains allowlists of trusted system processes

#### Event Classifier (`pkg/classifier/`)
- **Severity Scoring**: Assigns risk levels (LOW, WARN, HIGH, CRITICAL) to events
- **Context Analysis**: Considers process privileges, container context, and system state
- **Trust Assessment**: Evaluates whether events originate from trusted system components
- **False Positive Filtering**: Reduces noise by filtering legitimate operations

#### Alert System (`pkg/alert/`)
- **Multi-channel Dispatch**: Supports Slack, webhooks, and custom integrations
- **Rate Limiting**: Prevents alert storms with intelligent throttling
- **Message Formatting**: Rich alert messages with comprehensive context
- **Delivery Tracking**: Ensures reliable alert delivery with retry mechanisms

## PREREQUISITES

### System Requirements
- **Kubernetes Cluster**: Any supported Kubernetes version
- **Go Runtime**: Go 1.21 or higher for development
- **Container Runtime**: Docker, containerd, or compatible runtime

### Network Requirements
- **gRPC Port**: Port 50051 for agent communication
- **Outbound Connectivity**: Internet access for Slack/webhook notifications (optional)

## BUILDING

### Using Docker (Recommended)

```bash
# Build the container image
docker buildx build --platform linux/amd64 -t rasp-controller:latest .

# For k3s development: import into containerd
docker save rasp-controller:latest | sudo k3s ctr images import -
```

### Manual Build

```bash
# Clone and navigate to project
git clone <repository-url>
cd pod-controller

# Install dependencies and build
go mod tidy
go build -o bin/controller cmd/controller/main.go

# Generate protobuf code (if needed)
protoc --go_out=. --go-grpc_out=. pkg/telemetry/telemetry.proto
```

## DEPLOYMENT

### Kubernetes Deployment

1. **Create configuration**:
   ```bash
   kubectl apply -f deployments/pod-controller-config.yaml
   ```

2. **Deploy the controller**:
   ```bash
   kubectl apply -f deployments/pod-controller-kubernetes.yaml
   ```

3. **Verify deployment**:
   ```bash
   kubectl get pods -l app=rasp-controller
   kubectl logs -f deployment/rasp-controller
   ```

### Quick Development Deployment

```bash
# Use the provided script for rapid iteration
./redeploy_pod_controller.sh
```

## CONFIGURATION

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | gRPC server listening port | `50051` |
| `NODE_NAME` | Kubernetes node name | Auto-detected |
| `POD_NAME` | Controller pod name | Auto-detected |
| `LOG_LEVEL` | Logging verbosity | `info` |
| `DEBUG` | Debug mode flag | `info` |

### Alert Configuration

Configure alerting via ConfigMap or environment variables:

```yaml
# Alert Integration
SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/..."
SLACK_CHANNEL: "#security-alerts"
ALERT_WEBHOOK_URL: "https://your-webhook-endpoint.com/alerts"

# Alert Filtering
ALERT_EVENT_TYPES: "exec,setuid,mount"
ALERT_MIN_LEVEL: "warning"
ALERT_RATE_LIMIT: "10"  # alerts per minute
```

### Example Complete Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: rasp-controller-config
data:
  .env: |
    PORT=50051
    LOG_LEVEL=info
    SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
    SLACK_CHANNEL=#security-alerts
    ALERT_MIN_LEVEL=warning
    ALERT_RATE_LIMIT=10
```

## MONITORED EVENT TYPES

### Process Events
- **EXEC**: Process execution with command-line analysis
- **FORK**: Process creation and parent-child relationships

### Network Events
- **CONNECT**: Outbound network connections with destination analysis
- **BIND**: Socket binding operations
- **ACCEPT**: Incoming connection handling
- **SOCKET**: Socket creation monitoring

### File System Events
- **OPEN**: File access monitoring with path analysis
- **MOUNT/UMOUNT**: Filesystem mount operations
- **CHMOD**: File permission modifications

### Security Events
- **SETUID/SETGID**: Privilege escalation attempts
- **PTRACE**: Process debugging operations
- **CAPSET**: Linux capability modifications
- **BPF_PROG**: eBPF program loading
- **SECCOMP**: Syscall filtering changes

## THREAT DETECTION CAPABILITIES

### Critical Threats (Immediate Response)
- **Privilege Escalation**: Unauthorized `setuid` operations by non-system processes
- **Container Escape**: Suspicious mount operations to sensitive paths
- **Code Injection**: `ptrace` operations targeting critical processes
- **eBPF Attacks**: Unauthorized BPF program loading

### High-Severity Threats
- **Suspicious Execution**: Known attack tools and techniques
- **Network Anomalies**: Connections to suspicious ports or external IPs
- **File System Attacks**: Access to sensitive system files
- **Process Injection**: Suspicious `ptrace` operations

### Warning-Level Events
- **Anomalous Behavior**: Unusual process spawning patterns
- **Configuration Changes**: Seccomp modifications
- **Network Activity**: External connections from unexpected processes
- **File Modifications**: Changes to sensitive configuration files

### Threat Context Analysis
- **Process Trust Levels**: Maintains allowlists of trusted system processes
- **Container Context**: Considers pod labels, namespaces, and security contexts
- **Behavioral Patterns**: Tracks process spawning and network connection patterns
- **Privilege Analysis**: Evaluates event severity based on process privileges

## PERFORMANCE & SCALABILITY

### Resource Requirements
- **CPU**: 100-500m per controller instance
- **Memory**: 128-512MB per controller instance
- **Network**: ~1-10 Mbps depending on event volume

### Scalability Characteristics
- **Agent Connections**: Supports 1000+ concurrent agent connections
- **Event Throughput**: Processes 10,000+ events per second
- **Alert Processing**: Handles high-volume alert generation with rate limiting
- **Session Management**: Efficient agent session tracking and cleanup

### Performance Optimizations
- **Event Streaming**: Efficient gRPC streaming for minimal latency
- **Alert Aggregation**: Reduces noise through intelligent event grouping
- **Connection Pooling**: Optimized agent connection management
- **Memory Management**: Efficient Go garbage collection tuning

## OBSERVABILITY & MONITORING

### Health Checks
- **Startup Probe**: Verifies controller initialization
- **Liveness Probe**: Monitors ongoing controller health
- **Readiness Probe**: Ensures controller is ready to accept connections

### Logging
```bash
# View controller logs
kubectl logs -f deployment/rasp-controller

# Monitor specific log levels
kubectl logs deployment/rasp-controller | grep -i "error\|critical"
```

### Metrics
The controller provides detailed logging for:
- Agent connection statistics
- Event processing rates
- Threat detection counts
- Alert delivery status

## API REFERENCE

### gRPC Service Definition

```protobuf
service TelemetryService {
  // Agent lifecycle management
  rpc ConnectAgent(ConnectRequest) returns (ConnectResponse);
  rpc SendHeartbeat(Heartbeat) returns (ConnectionStatus);
  
  // Event processing
  rpc StreamEvents(stream SecurityEvent) returns (SendEventsResponse);
}
```

### Message Types

#### Agent Connection
```protobuf
message ConnectRequest {
  string agent_id = 1;
  string node_name = 2;
  string pod_name = 3;
}

message ConnectResponse {
  bool success = 1;
  string error_message = 2;
  string session_id = 3;
}
```

#### Security Events
```protobuf
message SecurityEvent {
  EventType event_type = 1;
  int32 pid = 2;
  int32 ppid = 3;
  string command = 4;
  string file_path = 5;
  google.protobuf.Timestamp timestamp = 8;
  map<string, string> container_context = 20;
  // Additional event-specific fields...
}
```

## DEVELOPMENT

### Local Development Setup

```bash
# Install dependencies
go mod tidy

# Run locally
go run cmd/controller/main.go

# Run tests
go test ./...

# Generate protobuf code
make proto
```

### Adding New Detection Rules

1. **Update Threat Detection** (`pkg/server/threat_detection.go`):
   ```go
   func (td *ThreatDetector) isNewThreatPattern(event *pb.SecurityEvent) bool {
       // Add new detection logic
   }
   ```

2. **Update Classification** (`pkg/classifier/classifier.go`):
   ```go
   case pb.EventType_NEW_EVENT:
       return SeverityHigh, "New threat detected"
   ```

3. **Add Tests**:
   ```go
   func TestNewThreatDetection(t *testing.T) {
       // Add test cases
   }
   ```

### Debugging

Enable debug logging:
```bash
# Set debug level
export LOG_LEVEL=debug

# Monitor detailed logs
kubectl logs -f deployment/rasp-controller | grep -i debug
```

## ALERT EXAMPLES

### Critical Alert - Privilege Escalation
```json
{
  "level": "CRITICAL",
  "title": "Privilege Escalation Detected",
  "message": "SETUID event detected in pod web-app/frontend: sh (Critical: Root privilege escalation detected)",
  "event_type": "SETUID",
  "container_context": {
    "pod_name": "frontend",
    "namespace": "web-app",
    "container_id": "abc123..."
  },
  "process_info": {
    "pid": "1234",
    "ppid": "1",
    "uid": "0",
    "command": "sh"
  }
}
```

### High Alert - Suspicious Network Activity
```json
{
  "level": "HIGH", 
  "title": "Suspicious Network Activity",
  "message": "CONNECT event detected: suspicious network activity from root process",
  "network_info": {
    "dst_ip": "192.168.1.100",
    "dst_port": "4444"
  }
}
```

## CONTRIBUTING

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow Go best practices and conventions
- Add comprehensive tests for new features
- Update documentation for API changes
- Ensure proper error handling and logging

## LICENSE

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Built for Kubernetes-native security monitoring and threat detection**
