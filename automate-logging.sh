#!/bin/bash

# RASP Monitoring Stack Deployment Script
# This script deploys a comprehensive observability stack for RASP monitoring
# using external configuration files for maintainability and customization.
#
# Configuration files (see configs/README.md for details):
# - configs/prometheus-values.yaml: Metrics collection and alerting
# - configs/grafana-values.yaml: Dashboards and visualization  
# - configs/fluent-bit-values.yaml: Log collection and parsing
#
# Usage: ./automate-logging.sh
# Access: ./access-monitoring.sh

set -e

# Configuration
NAMESPACE=logging
RASP_NAMESPACE=default  # Namespace where RASP controller is deployed
RASP_SERVICE=rasp-controller
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/configs"

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

# Check configuration files
check_config_files() {
    log_info "Checking configuration files..."
    
    if [ ! -d "$CONFIG_DIR" ]; then
        log_error "Configuration directory not found: $CONFIG_DIR"
        log_info "Please ensure you're running this script from the pod-controller directory"
        exit 1
    fi
    
    local missing_files=()
    local config_files=("prometheus-values.yaml" "grafana-values.yaml" "fluent-bit-values.yaml")
    
    for file in "${config_files[@]}"; do
        if [ ! -f "$CONFIG_DIR/$file" ]; then
            missing_files+=("$file")
        fi
    done
    
    if [ ${#missing_files[@]} -gt 0 ]; then
        log_error "Missing configuration files:"
        for file in "${missing_files[@]}"; do
            echo "  ❌ $CONFIG_DIR/$file"
        done
        echo ""
        log_info "📚 Please check the configs/README.md for configuration details"
        exit 1
    fi
    
    log_success "All configuration files found in $CONFIG_DIR"
    log_info "📝 You can customize configurations in:"
    echo "   • $CONFIG_DIR/prometheus-values.yaml (metrics collection)"
    echo "   • $CONFIG_DIR/grafana-values.yaml (dashboards)"
    echo "   • $CONFIG_DIR/fluent-bit-values.yaml (log collection)"
    echo "   📖 See $CONFIG_DIR/README.md for customization guide"
    echo ""
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
    
    # Check if config file exists
    if [ ! -f "$CONFIG_DIR/fluent-bit-values.yaml" ]; then
        log_error "Fluent Bit configuration file not found: $CONFIG_DIR/fluent-bit-values.yaml"
        return 1
    fi
    
    log_info "Using Fluent Bit configuration from: $CONFIG_DIR/fluent-bit-values.yaml"
    
    # Deploy Fluent Bit with values file
    helm upgrade --install fluent-bit fluent/fluent-bit \
      --namespace $NAMESPACE \
      --values "$CONFIG_DIR/fluent-bit-values.yaml" \
      --wait --timeout=300s
      
    log_success "Fluent Bit deployed with RASP log parsing"
}

# Deploy Prometheus with RASP monitoring
deploy_prometheus() {
    log_info "Deploying Prometheus with RASP controller monitoring..."
    
    # Check if config file exists
    if [ ! -f "$CONFIG_DIR/prometheus-values.yaml" ]; then
        log_error "Prometheus configuration file not found: $CONFIG_DIR/prometheus-values.yaml"
        return 1
    fi
    
    log_info "Using Prometheus configuration from: $CONFIG_DIR/prometheus-values.yaml"
    
    # Deploy Prometheus with values file
    helm upgrade --install prometheus prometheus-community/prometheus \
      --namespace $NAMESPACE \
      --values "$CONFIG_DIR/prometheus-values.yaml" \
      --wait --timeout=300s
      
    log_success "Prometheus deployed with RASP monitoring"
}

# Deploy Grafana with RASP dashboards
deploy_grafana() {
    log_info "Deploying Grafana with RASP dashboards..."
    
    # Check if config file exists
    if [ ! -f "$CONFIG_DIR/grafana-values.yaml" ]; then
        log_error "Grafana configuration file not found: $CONFIG_DIR/grafana-values.yaml"
        return 1
    fi
    
    log_info "Using Grafana configuration from: $CONFIG_DIR/grafana-values.yaml"
    
    # Create additional Grafana dashboard ConfigMap for RASP monitoring
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

    # Deploy Grafana with values file
    helm upgrade --install grafana grafana/grafana \
      --namespace $NAMESPACE \
      --values "$CONFIG_DIR/grafana-values.yaml" \
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
    echo "➡️  Controller Health: http://rasp-controller.default.svc.cluster.local:8080/health"
    echo "➡️  Controller Metrics: http://rasp-controller.default.svc.cluster.local:8080/api/v1/classifier/metrics"
    echo ""
    echo "🚀 Use the access helper script for easy dashboard access:"
    echo "  ./access-monitoring.sh"
    echo ""
    echo "📝 Configuration files used:"
    echo "  • configs/prometheus-values.yaml (metrics collection)"
    echo "  • configs/grafana-values.yaml (dashboards & visualization)"
    echo "  • configs/fluent-bit-values.yaml (log aggregation)"
    echo "  📖 See configs/README.md for customization guide"
    echo ""
    echo "To access services locally, use port-forwarding:"
    echo "  kubectl port-forward -n $NAMESPACE svc/kibana-kibana 5601:5601"
    echo "  kubectl port-forward -n $NAMESPACE svc/grafana 3000:80"
    echo "  kubectl port-forward -n $NAMESPACE svc/prometheus-server 9090:80"
}

# Main execution
main() {
    log_info "🚀 Starting RASP observability stack deployment..."
    echo ""
    
    check_rasp_controller
    check_config_files
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