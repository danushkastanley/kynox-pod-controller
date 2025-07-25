# RASP Monitoring Configuration Files

This directory contains Helm values files for deploying the RASP monitoring stack components. These configuration files are used by the `automate-logging.sh` script to deploy a comprehensive observability solution for your RASP system.

## CONFIGURATION FILES

### 1. `prometheus-values.yaml`
**Purpose**: Prometheus metrics collection and alerting configuration

**Key Features**:
- RASP controller metrics scraping (3 different endpoints)
- Kubernetes cluster monitoring (nodes, pods, services)
- Custom alerting rules for RASP-specific threats
- Resource limits and NodePort service configuration
- Built-in alert manager for notifications

**Customization**:
```yaml
# Modify scrape targets for your environment
- targets: ['your-rasp-service.namespace.svc.cluster.local:8080']

# Adjust resource limits based on cluster size
resources:
  requests:
    cpu: 100m      # Increase for larger clusters
    memory: 256Mi  # Increase for more metrics retention
```

### 2. `grafana-values.yaml`
**Purpose**: Grafana dashboard configuration with RASP visualizations

**Key Features**:
- Pre-configured Prometheus and Elasticsearch data sources
- RASP security monitoring dashboard
- Automatic dashboard discovery via sidecar
- Admin credentials and security settings
- NodePort service for external access

**Customization**:
```yaml
# Change default credentials (recommended for production)
adminUser: your-admin-user
adminPassword: your-secure-password

# Enable persistence for dashboard storage
persistence:
  enabled: true
  size: 10Gi

# Configure SMTP for alerting
smtp:
  enabled: true
  host: your-smtp-server:587
  user: your-email@domain.com
```

### 3. `fluent-bit-values.yaml`
**Purpose**: Log collection and parsing for RASP components

**Key Features**:
- Specialized RASP log parsing (controller and agent logs)
- Kubernetes metadata enrichment
- Elasticsearch output with proper indexing
- Custom parsers for different log formats
- Resource-efficient DaemonSet configuration

**Customization**:
```yaml
# Adjust log paths for custom deployments
Path: /var/log/containers/*your-rasp-prefix*.log

# Modify Elasticsearch output settings
Host: your-elasticsearch-host.namespace.svc.cluster.local
Index: your-custom-index-name

# Configure resource limits based on log volume
resources:
  limits:
    cpu: 200m     # Increase for high log volume
    memory: 256Mi # Increase for large log buffers
```

## ENVIRONMENT-SPECIFIC CONFIGURATIONS

### Development Environment
- Use the default configurations as provided
- Lower resource limits are acceptable
- NodePort services for easy access
- Persistence disabled for quick iteration

### Production Environment
**Recommended Changes**:

1. **Security**:
```yaml
# Grafana - Use secrets for credentials
adminPassword: $__file{/etc/secrets/admin_password}

# Prometheus - Enable TLS and authentication
serverFiles:
  prometheus.yml:
    global:
      external_labels:
        environment: 'production'
```

2. **Persistence**:
```yaml
# Enable persistent storage
persistentVolume:
  enabled: true
  size: 50Gi  # Adjust based on retention needs
  storageClass: fast-ssd
```

3. **Resources**:
```yaml
# Increase resource limits
resources:
  requests:
    cpu: 500m
    memory: 1Gi
  limits:
    cpu: 2000m
    memory: 4Gi
```

4. **High Availability**:
```yaml
# Grafana - Multiple replicas
replicas: 2

# Prometheus - Add external storage
serverFiles:
  prometheus.yml:
    global:
      external_labels:
        replica: '{{ .Pod.Name }}'
```

## CUSTOMIZING FOR YOUR ENVIRONMENT

### 1. RASP Service Configuration
Update the RASP controller service name and namespace in `prometheus-values.yaml`:
```yaml
- targets: ['your-rasp-controller.your-namespace.svc.cluster.local:8080']
```

### 2. Log Collection Paths
Modify Fluent Bit log paths in `fluent-bit-values.yaml`:
```yaml
Path: /var/log/containers/*your-rasp-pattern*.log
```

### 3. Dashboard Customization
Add custom dashboards to Grafana configuration:
```yaml
dashboards:
  your-custom-folder:
    your-dashboard-name:
      gnetId: 12345  # Import from Grafana.com
      revision: 1
      datasource: Prometheus
```

### 4. Alerting Rules
Customize Prometheus alerting in `prometheus-values.yaml`:
```yaml
alerting_rules.yml:
  groups:
    - name: your-custom-alerts
      rules:
        - alert: YourCustomAlert
          expr: your_metric > threshold
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Your custom alert description"
```

## METRICS AND DASHBOARDS

### Available RASP Metrics
The configuration automatically collects these metrics from your RASP controller:

- `rasp_events_total` - Total security events by type
- `rasp_threats_detected_total` - Detected threats by severity
- `rasp_agent_connections` - Active agent connections
- `rasp_controller_uptime` - Controller uptime
- `rasp_event_processing_duration` - Event processing latency

### Dashboard Panels
The included dashboard provides:

1. **System Overview**: Controller status, uptime, agent connections
2. **Security Events**: Event rates, types, and trends
3. **Threat Detection**: Threat severity breakdown and rates
4. **Performance**: Processing latency and resource usage
5. **Agent Health**: Connection status and event forwarding rates

## DEPLOYMENT

To use these configurations:

1. **Direct Deployment**:
```bash
cd pod-controller
./automate-logging.sh
```

2. **Custom Configuration**:
```bash
# Edit configuration files as needed
vim configs/prometheus-values.yaml
vim configs/grafana-values.yaml
vim configs/fluent-bit-values.yaml

# Deploy with your changes
./automate-logging.sh
```

3. **Verify Deployment**:
```bash
./access-monitoring.sh
```

## TROUBLESHOOTING

### Common Issues

1. **Configuration File Not Found**:
```bash
# Ensure you're running from the correct directory
cd pod-controller
ls configs/  # Should show all .yaml files
```

2. **Helm Values Errors**:
```bash
# Validate YAML syntax
yamllint configs/prometheus-values.yaml
```

3. **Service Discovery Issues**:
```bash
# Check RASP controller service name
kubectl get svc -n default | grep rasp
# Update targets in prometheus-values.yaml accordingly
```

4. **Resource Constraints**:
```bash
# Check if pods are running
kubectl get pods -n logging
# Adjust resource limits in configuration files if needed
```

## ADDITIONAL RESOURCES

- [Prometheus Configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
- [Grafana Provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/)
- [Fluent Bit Configuration](https://docs.fluentbit.io/manual/administration/configuring-fluent-bit) 