#!/bin/bash

# RASP Monitoring Stack Cleanup Script
# This script removes the monitoring stack for clean redeployment

set -e

# Configuration
NAMESPACE=logging

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

# Remove Helm releases
cleanup_helm_releases() {
    log_info "Removing Helm releases..."
    
    releases=("grafana" "prometheus" "fluent-bit" "kibana" "elasticsearch")
    
    for release in "${releases[@]}"; do
        if helm list -n $NAMESPACE | grep -q "$release"; then
            log_info "Removing $release..."
            helm uninstall $release -n $NAMESPACE || true
        else
            log_info "$release not found, skipping..."
        fi
    done
    
    log_success "Helm releases removed"
}

# Remove PVCs and ConfigMaps
cleanup_resources() {
    log_info "Removing persistent volumes and ConfigMaps..."
    
    # Remove PVCs
    kubectl delete pvc --all -n $NAMESPACE || true
    
    # Remove ConfigMaps
    kubectl delete configmap --all -n $NAMESPACE || true
    
    # Remove secrets
    kubectl delete secret --all -n $NAMESPACE || true
    
    log_success "Resources cleaned up"
}

# Remove namespace
cleanup_namespace() {
    log_info "Removing namespace $NAMESPACE..."
    kubectl delete namespace $NAMESPACE || true
    
    # Wait for namespace to be deleted
    log_info "Waiting for namespace deletion..."
    kubectl wait --for=delete namespace/$NAMESPACE --timeout=120s || true
    
    log_success "Namespace removed"
}

# Main execution
main() {
    log_info "🧹 Starting RASP monitoring stack cleanup..."
    echo ""
    
    read -p "Are you sure you want to remove the entire monitoring stack? (y/N): " confirm
    if [[ $confirm != [yY] ]]; then
        log_info "Cleanup cancelled"
        exit 0
    fi
    
    cleanup_helm_releases
    cleanup_resources
    cleanup_namespace
    
    log_success "✅ RASP monitoring stack cleanup completed!"
    echo ""
    log_info "You can now redeploy with: ./automate-logging.sh"
}

# Run main function
main "$@" 