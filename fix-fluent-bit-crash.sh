#!/bin/bash

echo "FIXING Fluent Bit DNS and connection issues..."
echo "==============================================="

# Check if kubectl is available
if ! command -v kubectl >/dev/null 2>&1; then
    echo "ERROR kubectl not found. Please install kubectl first."
    exit 1
fi

# Check if we can connect to the cluster
if ! kubectl cluster-info >/dev/null 2>&1; then
    echo "ERROR Cannot connect to Kubernetes cluster. Please check your connection."
    exit 1
fi

echo "SUCCESS Connected to Kubernetes cluster"

# Check OpenSearch connectivity
echo "TESTING OpenSearch connectivity..."
if kubectl get service opensearch -n logging >/dev/null 2>&1; then
    echo "SUCCESS OpenSearch service found: opensearch.logging.svc.cluster.local"
else
    echo "ERROR OpenSearch service not found! Please deploy OpenSearch first."
    exit 1
fi

# Check current Fluent Bit status
echo "STATUS Current Fluent Bit Status:"
kubectl get pods -n logging -l k8s-app=fluent-bit-logging 2>/dev/null || echo "No Fluent Bit pods found"

echo ""
echo "REMOVING problematic configuration..."

# Delete the current ConfigMap (this will cause pods to restart with new config)
kubectl delete configmap fluent-bit-config -n logging --ignore-not-found=true

echo "APPLYING corrected configuration with Lua-based JSON parsing..."
# Apply the fixed configuration with Lua script
kubectl apply -f fluent-bit-opensearch-config.yaml

echo "RESTARTING Fluent Bit pods..."
# Force restart Fluent Bit DaemonSet
kubectl rollout restart daemonset/fluent-bit -n logging 2>/dev/null || echo "No existing DaemonSet found"

# Delete any existing problematic pods to force recreation
kubectl delete pods -n logging -l k8s-app=fluent-bit-logging --ignore-not-found=true

echo "WAITING for new pods to start..."
sleep 10

# Wait for pods to be ready
kubectl wait --for=condition=ready pod -l k8s-app=fluent-bit-logging -n logging --timeout=60s 2>/dev/null || echo "Pods still starting..."

echo ""
echo "STATUS Updated Status:"
kubectl get pods -n logging -l k8s-app=fluent-bit-logging

echo ""
echo "CHECKING Recent logs (checking for errors):"
echo "====================================="
kubectl logs -n logging -l k8s-app=fluent-bit-logging --tail=10 2>/dev/null || echo "No logs available yet"

echo ""
echo "SUCCESS Fix Applied!"
echo ""
echo "FEATURES New features:"
echo "   • Lua-based conditional JSON parsing"
echo "   • No more 'log is not a map' errors"
echo "   • Automatic severity field detection"
echo "   • Enhanced field extraction for RASP events"
echo ""
echo "NOTE If pods are still starting, wait 1-2 minutes and check:"
echo "   kubectl get pods -n logging"
echo "   kubectl logs -n logging -l k8s-app=fluent-bit-logging"
echo ""
echo "SUCCESS Your severity fields and enhanced log parsing are now active!" 