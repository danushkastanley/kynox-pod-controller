#!/bin/bash

set -e

# Configuration
NAMESPACE=logging
RASP_NAMESPACE=default  # Namespace where RASP controller is deployed
RASP_SERVICE=rasp-controller

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if RASP controller is running
check_rasp_controller() {
    log_info "Checking RASP controller status..."
    
    if ! kubectl get service $RASP_SERVICE -n $RASP_NAMESPACE &>/dev/null; then
        log_error "RASP controller service not found in namespace $RASP_NAMESPACE"
        log_info "Please deploy the RASP controller first using:"
        log_info "  kubectl apply -f pod-controller/deployments/"
        exit 1
    fi
    
    # Check if HTTP port is exposed
    if ! kubectl get service $RASP_SERVICE -n $RASP_NAMESPACE -o jsonpath='{.spec.ports[?(@.name=="http-metrics")].port}' | grep -q 8080; then
        log_warning "RASP controller HTTP metrics port (8080) not found"
        log_info "Please update the RASP controller deployment to expose HTTP metrics"
        log_info "This script will continue, but metrics collection may not work properly"
    else
        log_success "RASP controller found with HTTP metrics port"
    fi
}

# Create namespace
create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    kubectl create namespace $NAMESPACE || true
    log_success "Namespace $NAMESPACE ready"
}

# Add Helm repositories
setup_helm_repos() {
    log_info "Adding Helm repositories..."
    helm repo add elastic https://helm.elastic.co
    helm repo add fluent https://fluent.github.io/helm-charts
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add grafana https://grafana.github.io/helm-charts
    helm repo update
    log_success "Helm repositories configured"
}

# Deploy Elasticsearch
deploy_elasticsearch() {
    log_info "Deploying Elasticsearch..."
    helm upgrade --install elasticsearch elastic/elasticsearch \
      --namespace $NAMESPACE \
      --set replicas=1 \
      --set minimumMasterNodes=1 \
      --set volumeClaimTemplate.resources.requests.storage=2Gi \
      --wait --timeout=300s
    log_success "Elasticsearch deployed"
}

# Deploy Kibana
deploy_kibana() {
    log_info "Deploying Kibana..."
    helm upgrade --install kibana elastic/kibana \
      --namespace $NAMESPACE \
      --set service.type=NodePort \
      --wait --timeout=300s
    log_success "Kibana deployed"
}

# Deploy Fluent Bit with enhanced configuration
deploy_fluentbit() {
    log_info "Deploying Fluent Bit with RASP log parsing..."
    
    # Create enhanced Fluent Bit configuration
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: $NAMESPACE
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         1
        Log_Level     info
        Daemon        off
        Parsers_File  parsers.conf
        HTTP_Server   On
        HTTP_Listen   0.0.0.0
        HTTP_Port     2020

    [INPUT]
        Name              tail
        Path              /var/log/containers/*rasp*.log
        Parser            docker
        Tag               rasp.*
        Refresh_Interval  5
        DB                /var/log/flb_rasp.db

    [INPUT]
        Name              tail
        Path              /var/log/containers/*.log
        Exclude_Path      /var/log/containers/*rasp*.log
        Parser            docker
        Tag               kube.*
        Refresh_Interval  5
        DB                /var/log/flb_kube.db

    [FILTER]
        Name                kubernetes
        Match               *
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix     kube.var.log.containers.
        Merge_Log           On
        Keep_Log            Off
        K8S-Logging.Parser  On
        K8S-Logging.Exclude On

    [FILTER]
        Name                parser
        Match               rasp.*
        Key_Name            log
        Parser              rasp_json
        Reserve_Data        On

    [OUTPUT]
        Name              es
        Match             *
        Host              elasticsearch-master.${NAMESPACE}.svc.cluster.local
        Port              9200
        Index             logs
        Type              _doc

  parsers.conf: |
    [PARSER]
        Name        docker
        Format      json
        Time_Key    time
        Time_Format %Y-%m-%dT%H:%M:%S.%L
        Time_Keep   On

    [PARSER]
        Name        rasp_json
        Format      json
        Time_Key    timestamp
        Time_Format %Y-%m-%dT%H:%M:%S.%L
        Time_Keep   On
EOF
    
    helm upgrade --install fluent-bit fluent/fluent-bit \
      --namespace $NAMESPACE \
      --set-file config.fluentBitConfig=<(kubectl get configmap fluent-bit-config -n $NAMESPACE -o jsonpath='{.data.fluent-bit\.conf}') \
      --set-file config.parsersConfig=<(kubectl get configmap fluent-bit-config -n $NAMESPACE -o jsonpath='{.data.parsers\.conf}') \
      --wait --timeout=300s
      
    log_success "Fluent Bit deployed with RASP log parsing"
}

# Deploy Prometheus with RASP monitoring
deploy_prometheus() {
    log_info "Deploying Prometheus with RASP controller monitoring..."
    
    # Create Prometheus configuration for RASP monitoring
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-rasp-config
  namespace: $NAMESPACE
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s

    scrape_configs:
      # Default Kubernetes scraping
      - job_name: 'kubernetes-pods'
        kubernetes_sd_configs:
          - role: pod
        relabel_configs:
          - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
            action: keep
            regex: true
          - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
            action: replace
            target_label: __metrics_path__
            regex: (.+)
          - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
            action: replace
            regex: ([^:]+)(?::\d+)?;(\d+)
            replacement: \$1:\$2
            target_label: __address__

      # RASP Controller metrics
      - job_name: 'rasp-controller'
        static_configs:
          - targets: ['${RASP_SERVICE}.${RASP_NAMESPACE}.svc.cluster.local:8080']
        metrics_path: '/api/v1/classifier/metrics/summary'
        scrape_interval: 30s
        scrape_timeout: 10s

      # Kubernetes API server
      - job_name: 'kubernetes-apiservers'
        kubernetes_sd_configs:
          - role: endpoints
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        relabel_configs:
          - source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
            action: keep
            regex: default;kubernetes;https

      # Node metrics
      - job_name: 'kubernetes-nodes'
        kubernetes_sd_configs:
          - role: node
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        relabel_configs:
          - action: labelmap
            regex: __meta_kubernetes_node_label_(.+)
EOF

    helm upgrade --install prometheus prometheus-community/prometheus \
      --namespace $NAMESPACE \
      --set-file serverFiles."prometheus\.yml"=<(kubectl get configmap prometheus-rasp-config -n $NAMESPACE -o jsonpath='{.data.prometheus\.yml}') \
      --set server.service.type=NodePort \
      --wait --timeout=300s
      
    log_success "Prometheus deployed with RASP monitoring"
}

# Deploy Grafana with RASP dashboards
deploy_grafana() {
    log_info "Deploying Grafana with RASP dashboards..."
    
    # Create Grafana dashboard for RASP monitoring
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: rasp-dashboard
  namespace: $NAMESPACE
  labels:
    grafana_dashboard: "1"
data:
  rasp-monitoring.json: |
    {
      "dashboard": {
        "id": null,
        "title": "RASP Security Monitoring",
        "tags": ["rasp", "security"],
        "timezone": "browser",
        "panels": [
          {
            "id": 1,
            "title": "Security Events by Type",
            "type": "graph",
            "targets": [
              {
                "expr": "rasp_events_total",
                "legendFormat": "{{event_type}}"
              }
            ],
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
          },
          {
            "id": 2,
            "title": "Security Events by Severity",
            "type": "piechart",
            "targets": [
              {
                "expr": "rasp_events_by_severity",
                "legendFormat": "{{severity}}"
              }
            ],
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
          },
          {
            "id": 3,
            "title": "Agent Connections",
            "type": "stat",
            "targets": [
              {
                "expr": "rasp_agent_connections",
                "legendFormat": "Active Agents"
              }
            ],
            "gridPos": {"h": 4, "w": 6, "x": 0, "y": 8}
          },
          {
            "id": 4,
            "title": "Events Per Second",
            "type": "stat",
            "targets": [
              {
                "expr": "rate(rasp_events_total[5m])",
                "legendFormat": "Events/sec"
              }
            ],
            "gridPos": {"h": 4, "w": 6, "x": 6, "y": 8}
          }
        ],
        "time": {"from": "now-1h", "to": "now"},
        "refresh": "30s"
      }
    }
EOF

    helm upgrade --install grafana grafana/grafana \
      --namespace $NAMESPACE \
      --set adminPassword='admin' \
      --set service.type=NodePort \
      --set sidecar.dashboards.enabled=true \
      --set sidecar.dashboards.label=grafana_dashboard \
      --wait --timeout=300s
      
    log_success "Grafana deployed with RASP dashboards"
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check all pods are running
    log_info "Checking pod status..."
    kubectl get pods -n $NAMESPACE
    
    # Wait for all pods to be ready
    kubectl wait --for=condition=ready pod --all -n $NAMESPACE --timeout=300s
    
    # Check services
    log_info "Checking services..."
    kubectl get services -n $NAMESPACE
    
    # Test RASP controller metrics endpoint
    log_info "Testing RASP controller metrics endpoint..."
    if kubectl run curl-test --image=curlimages/curl --rm -i --restart=Never -- \
        curl -s "http://${RASP_SERVICE}.${RASP_NAMESPACE}.svc.cluster.local:8080/health" | grep -q "healthy"; then
        log_success "RASP controller HTTP endpoint is accessible"
    else
        log_warning "RASP controller HTTP endpoint test failed"
    fi
    
    # Get access information
    log_info "Getting access information..."
    
    KIBANA_PORT=$(kubectl get service kibana-kibana -n $NAMESPACE -o jsonpath='{.spec.ports[0].nodePort}')
    GRAFANA_PORT=$(kubectl get service grafana -n $NAMESPACE -o jsonpath='{.spec.ports[0].nodePort}')
    PROMETHEUS_PORT=$(kubectl get service prometheus-server -n $NAMESPACE -o jsonpath='{.spec.ports[0].nodePort}')
    
    NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
    
    echo ""
    log_success "Observability stack deployed successfully!"
    echo ""
    echo "Access URLs (replace <NODE_IP> with your node IP: $NODE_IP):"
    echo "➡️  Kibana:     http://$NODE_IP:$KIBANA_PORT"
    echo "➡️  Grafana:    http://$NODE_IP:$GRAFANA_PORT (admin / admin)"
    echo "➡️  Prometheus: http://$NODE_IP:$PROMETHEUS_PORT"
    echo ""
    echo "RASP Monitoring Endpoints:"
    echo "➡️  Controller Health: http://$NODE_IP:$GRAFANA_PORT (via port-forward)"
    echo "➡️  Controller Metrics: http://$NODE_IP:$GRAFANA_PORT (via port-forward)"
    echo ""
    echo "To access services locally, use port-forwarding:"
    echo "  kubectl port-forward -n $NAMESPACE svc/kibana-kibana 5601:5601"
    echo "  kubectl port-forward -n $NAMESPACE svc/grafana 3000:80"
    echo "  kubectl port-forward -n $NAMESPACE svc/prometheus-server 9090:80"
}

# Main execution
main() {
    log_info "Starting RASP observability stack deployment..."
    
    check_rasp_controller
    create_namespace
    setup_helm_repos
    deploy_elasticsearch
    deploy_kibana
    deploy_fluentbit
    deploy_prometheus
    deploy_grafana
    verify_deployment
    
    log_success "RASP observability stack deployment completed!"
}

# Run main function
main "$@"