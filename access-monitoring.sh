#!/bin/bash

# RASP Monitoring Access Script
# This script helps you access the monitoring dashboards

set -e

# Configuration
NAMESPACE=logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
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

# Check if namespace exists
check_namespace() {
    if ! kubectl get namespace $NAMESPACE >/dev/null 2>&1; then
        log_error "Namespace '$NAMESPACE' not found. Please deploy the monitoring stack first."
        exit 1
    fi
}

# Check pod status
check_pods() {
    log_info "Checking monitoring stack status..."
    
    # Check if pods are running
    if kubectl get pods -n $NAMESPACE | grep -E "(grafana|prometheus|kibana|elasticsearch)" | grep -v Running >/dev/null; then
        log_warning "Some monitoring pods are not running yet:"
        kubectl get pods -n $NAMESPACE | grep -E "(grafana|prometheus|kibana|elasticsearch)"
        echo ""
    fi
    
    log_info "Current pod status:"
    kubectl get pods -n $NAMESPACE | grep -E "(grafana|prometheus|kibana|elasticsearch|fluent-bit)"
    echo ""
}

# Get service information
get_service_info() {
    log_info "Getting service information..."
    
    # Try to get NodePort services
    KIBANA_PORT=$(kubectl get service -n $NAMESPACE 2>/dev/null | grep kibana | awk '{print $5}' | cut -d: -f2 | cut -d/ -f1 || echo "")
    GRAFANA_PORT=$(kubectl get service -n $NAMESPACE 2>/dev/null | grep grafana | awk '{print $5}' | cut -d: -f2 | cut -d/ -f1 || echo "")
    PROMETHEUS_PORT=$(kubectl get service -n $NAMESPACE 2>/dev/null | grep prometheus-server | awk '{print $5}' | cut -d: -f2 | cut -d/ -f1 || echo "")
    
    NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || echo "localhost")
    
    echo ""
    log_info "Service Access Information:"
    echo "----------------------------------------"
    
    if [ ! -z "$GRAFANA_PORT" ] && [ "$GRAFANA_PORT" != "80" ]; then
        echo "🎯 Grafana:    http://$NODE_IP:$GRAFANA_PORT"
        echo "   Credentials: admin / admin"
    else
        echo "🎯 Grafana:    Use port-forward (see commands below)"
    fi
    
    if [ ! -z "$PROMETHEUS_PORT" ] && [ "$PROMETHEUS_PORT" != "80" ]; then
        echo "📊 Prometheus: http://$NODE_IP:$PROMETHEUS_PORT"
    else
        echo "📊 Prometheus: Use port-forward (see commands below)"
    fi
    
    if [ ! -z "$KIBANA_PORT" ] && [ "$KIBANA_PORT" != "5601" ]; then
        echo "🔍 Kibana:     http://$NODE_IP:$KIBANA_PORT"
    else
        echo "🔍 Kibana:     Use port-forward (see commands below)"
    fi
    
    echo ""
}

# Show port forwarding commands
show_port_forward_commands() {
    log_info "Port-Forward Commands (run in separate terminals):"
    echo "----------------------------------------"
    echo "# Access Grafana locally on http://localhost:3000"
    echo "kubectl port-forward -n $NAMESPACE svc/grafana 3000:80"
    echo ""
    echo "# Access Prometheus locally on http://localhost:9090"
    echo "kubectl port-forward -n $NAMESPACE svc/prometheus-server 9090:80"
    echo ""
    echo "# Access Kibana locally on http://localhost:5601"
    echo "kubectl port-forward -n $NAMESPACE svc/kibana-kibana 5601:5601"
    echo ""
}

# Test RASP controller connectivity
test_rasp_controller() {
    log_info "Testing RASP Controller connectivity..."
    
    # Test if RASP controller is accessible
    if kubectl run curl-test --image=curlimages/curl --rm -i --restart=Never --timeout=30s -- \
        curl -s -f "http://rasp-controller.default.svc.cluster.local:8080/health" >/dev/null 2>&1; then
        log_success "✅ RASP Controller HTTP endpoint is accessible"
    else
        log_warning "⚠️  RASP Controller HTTP endpoint test failed"
        log_info "Make sure the RASP controller is deployed and running:"
        echo "kubectl get pods -n default | grep rasp-controller"
    fi
    
    echo ""
}

# Check RASP metrics in Prometheus
check_rasp_metrics() {
    log_info "RASP Metrics Information:"
    echo "----------------------------------------"
    echo "📈 Available RASP Metrics Endpoints:"
    echo "   • http://rasp-controller.default.svc.cluster.local:8080/health"
    echo "   • http://rasp-controller.default.svc.cluster.local:8080/api/v1/classifier/metrics"
    echo "   • http://rasp-controller.default.svc.cluster.local:8080/api/v1/classifier/metrics/summary"
    echo ""
    echo "🎯 In Grafana, look for:"
    echo "   • RASP Security Monitoring Dashboard"
    echo "   • Prometheus data source should show 'rasp-controller' targets"
    echo ""
    echo "🔍 In Prometheus, check targets:"
    echo "   • Status > Targets > rasp-controller job"
    echo ""
}

# Main execution
main() {
    echo ""
    log_info "🚀 RASP Monitoring Access Helper"
    echo "=================================="
    
    check_namespace
    check_pods
    get_service_info
    show_port_forward_commands
    test_rasp_controller
    check_rasp_metrics
    
    log_success "Ready to access your RASP monitoring stack!"
    echo ""
    log_info "💡 Quick Start:"
    echo "1. Run port-forward commands in separate terminals"
    echo "2. Access Grafana at http://localhost:3000 (admin/admin)"
    echo "3. Import the RASP dashboard if not already loaded"
    echo "4. Check Prometheus targets are healthy"
    echo ""
}

# Handle command line arguments
case "${1:-help}" in
    "pods")
        check_pods
        ;;
    "services")
        get_service_info
        ;;
    "test")
        test_rasp_controller
        ;;
    "forward")
        show_port_forward_commands
        ;;
    "help"|*)
        main
        ;;
esac 