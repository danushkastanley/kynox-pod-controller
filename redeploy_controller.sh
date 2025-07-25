#!/bin/bash

# Script to redeploy pod-controller with fixed Slack alerting
echo "REDEPLOYING pod-controller with improved Slack alerting..."

# Build the Docker image
echo "BUILDING Docker image..."
docker buildx build --platform linux/amd64 -t rasp-controller:latest . --load

# If using k3s, import into containerd
if command -v k3s &> /dev/null; then
    echo "IMPORTING image into k3s..."
    docker save rasp-controller:latest | sudo k3s ctr images import -
fi

# Delete existing deployment
echo "REMOVING existing deployment..."
kubectl delete deployment rasp-controller 2>/dev/null || echo "No existing deployment found"

# Apply configuration and deployment
echo "APPLYING configuration..."
kubectl apply -f deployments/pod-controller-config.yaml

echo "DEPLOYING updated controller..."
kubectl apply -f deployments/pod-controller-kubernetes.yaml

# Wait for rollout
echo "WAITING for deployment to complete..."
kubectl rollout status deployment/rasp-controller --timeout=300s

# Check pod status
echo "STATUS Deployment status:"
kubectl get pods -l app=rasp-controller
kubectl get deployment rasp-controller

echo "SUCCESS Deployment complete! Check logs with:"
echo "   kubectl logs -f deployment/rasp-controller" 