#!/bin/bash

# Script to redeploy pod-controller with fixed Slack alerting
echo "🔧 Redeploying pod-controller with improved Slack alerting..."

# Build the Docker image
echo "📦 Building Docker image..."
docker buildx build --platform linux/amd64 -t rasp-controller:latest . --load

# If using k3s, import into containerd
if command -v k3s &> /dev/null; then
    echo "📤 Importing image into k3s..."
    docker save rasp-controller:latest | sudo k3s ctr images import -
fi

# Delete existing deployment
echo "🗑️  Removing existing deployment..."
kubectl delete deployment rasp-controller 2>/dev/null || echo "No existing deployment found"

# Apply configuration and deployment
echo "⚙️  Applying configuration..."
kubectl apply -f deployments/pod-controller-config.yaml

echo "🚀 Deploying updated controller..."
kubectl apply -f deployments/pod-controller-kubernetes.yaml

# Wait for rollout
echo "⏳ Waiting for deployment to complete..."
kubectl rollout status deployment/rasp-controller --timeout=300s

# Check pod status
echo "📊 Deployment status:"
kubectl get pods -l app=rasp-controller
kubectl get deployment rasp-controller

echo "✅ Deployment complete! Check logs with:"
echo "   kubectl logs -f deployment/rasp-controller" 