#!/bin/bash

echo "🚀 Updating Fluent Bit for Enhanced RASP Log Parsing..."
echo "====================================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if kubectl is available
if ! command_exists kubectl; then
    echo "❌ kubectl not found. Please install kubectl first."
    exit 1
fi

# Check if we can connect to the cluster
if ! kubectl cluster-info >/dev/null 2>&1; then
    echo "❌ Cannot connect to Kubernetes cluster. Please check your connection."
    exit 1
fi

echo "✅ Connected to Kubernetes cluster"

# Check if logging namespace exists
if ! kubectl get namespace logging >/dev/null 2>&1; then
    echo "📝 Creating logging namespace..."
    kubectl create namespace logging
else
    echo "✅ Logging namespace exists"
fi

# Backup existing Fluent Bit configuration (if exists)
echo "💾 Backing up existing Fluent Bit configuration..."
kubectl get daemonset fluent-bit -n logging -o yaml > fluent-bit-backup-$(date +%Y%m%d-%H%M%S).yaml 2>/dev/null || echo "ℹ️ No existing Fluent Bit found to backup"

# Delete existing Fluent Bit if it exists
echo "🗑️ Removing old Fluent Bit deployment..."
kubectl delete daemonset fluent-bit -n logging --ignore-not-found=true
kubectl delete configmap fluent-bit-config -n logging --ignore-not-found=true
kubectl delete serviceaccount fluent-bit -n logging --ignore-not-found=true
kubectl delete clusterrole fluent-bit-read --ignore-not-found=true
kubectl delete clusterrolebinding fluent-bit-read --ignore-not-found=true

echo "⏳ Waiting for old pods to terminate..."
sleep 10

# Apply new configuration
echo "📋 Applying new Fluent Bit ConfigMap..."
kubectl apply -f fluent-bit-opensearch-config.yaml

echo "🚀 Deploying enhanced Fluent Bit DaemonSet..."
kubectl apply -f fluent-bit-daemonset.yaml

echo "⏳ Waiting for Fluent Bit pods to start..."
kubectl wait --for=condition=ready pod -l k8s-app=fluent-bit-logging -n logging --timeout=120s

# Check status
echo ""
echo "📊 Deployment Status:"
echo "==================="
kubectl get pods -n logging -l k8s-app=fluent-bit-logging

echo ""
echo "🔍 Quick Health Check:"
echo "====================="
kubectl logs -n logging -l k8s-app=fluent-bit-logging --tail=5

echo ""
echo "✅ Fluent Bit Update Complete!"
echo ""
echo "🎯 What's New:"
echo "  • Enhanced JSON parsing for RASP logs"
echo "  • Structured field extraction"
echo "  • Better OpenSearch integration"
echo "  • Separate processing for RASP vs general logs"
echo ""
echo "📋 Next Steps:"
echo "  1. Wait 2-3 minutes for new logs to be processed"
echo "  2. Refresh your OpenSearch Dashboards index patterns"
echo "  3. Create visualizations with the new structured fields"
echo ""
echo "🏃‍♂️ To create demo dashboards, run:"
echo "   ./create-demo-dashboards.sh" 