#!/bin/bash

# Simple RASP Logging Stack with OpenSearch
# This script deploys a lightweight observability stack using OpenSearch instead of Elasticsearch

set -e

NAMESPACE=logging

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Create namespace
create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    kubectl create namespace $NAMESPACE || true
    log_success "Namespace ready"
}

# Deploy OpenSearch (simpler than Elasticsearch)
deploy_opensearch() {
    log_info "Deploying OpenSearch..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opensearch
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: opensearch
  template:
    metadata:
      labels:
        app: opensearch
    spec:
      containers:
      - name: opensearch
        image: opensearchproject/opensearch:2.11.0
        env:
        - name: discovery.type
          value: single-node
        - name: OPENSEARCH_JAVA_OPTS
          value: "-Xms256m -Xmx256m"
        - name: DISABLE_SECURITY_PLUGIN
          value: "true"
        - name: DISABLE_INSTALL_DEMO_CONFIG
          value: "true"
        ports:
        - containerPort: 9200
        - containerPort: 9300
        volumeMounts:
        - name: opensearch-data
          mountPath: /usr/share/opensearch/data
        resources:
          requests:
            memory: "512Mi"
            cpu: "200m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: opensearch-data
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: opensearch
  namespace: $NAMESPACE
spec:
  selector:
    app: opensearch
  ports:
  - name: http
    port: 9200
    targetPort: 9200
  - name: transport
    port: 9300
    targetPort: 9300
EOF
    
    log_success "OpenSearch deployed"
}

# Deploy OpenSearch Dashboards (simpler than Kibana)
deploy_opensearch_dashboards() {
    log_info "Deploying OpenSearch Dashboards..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opensearch-dashboards
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: opensearch-dashboards
  template:
    metadata:
      labels:
        app: opensearch-dashboards
    spec:
      containers:
      - name: opensearch-dashboards
        image: opensearchproject/opensearch-dashboards:2.11.0
        env:
        - name: OPENSEARCH_HOSTS
          value: "http://opensearch:9200"
        - name: DISABLE_SECURITY_DASHBOARDS_PLUGIN
          value: "true"
        ports:
        - containerPort: 5601
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "300m"
---
apiVersion: v1
kind: Service
metadata:
  name: opensearch-dashboards
  namespace: $NAMESPACE
spec:
  type: NodePort
  selector:
    app: opensearch-dashboards
  ports:
  - port: 5601
    targetPort: 5601
    nodePort: 30001
EOF
    
    log_success "OpenSearch Dashboards deployed"
}

# Deploy simple Fluent Bit
deploy_simple_fluentbit() {
    log_info "Deploying Fluent Bit..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluent-bit
  namespace: $NAMESPACE
spec:
  selector:
    matchLabels:
      app: fluent-bit
  template:
    metadata:
      labels:
        app: fluent-bit
    spec:
      containers:
      - name: fluent-bit
        image: fluent/fluent-bit:2.2.0
        env:
        - name: FLUENT_OPENSEARCH_HOST
          value: "opensearch"
        - name: FLUENT_OPENSEARCH_PORT
          value: "9200"
        volumeMounts:
        - name: varlog
          mountPath: /var/log
          readOnly: true
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
        - name: fluent-bit-config
          mountPath: /fluent-bit/etc/fluent-bit.conf
          subPath: fluent-bit.conf
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
      - name: fluent-bit-config
        configMap:
          name: fluent-bit-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: $NAMESPACE
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         5
        Log_Level     info
        Daemon        off
        Parsers_File  parsers.conf
        HTTP_Server   On
        HTTP_Listen   0.0.0.0
        HTTP_Port     2020

    [INPUT]
        Name              tail
        Path              /var/log/containers/*rasp-controller*.log
        Parser            docker
        Tag               rasp.controller
        Refresh_Interval  5

    [INPUT]
        Name              tail
        Path              /var/log/containers/*pod-agent*.log
        Parser            docker
        Tag               rasp.agent
        Refresh_Interval  5

    [INPUT]
        Name              tail
        Path              /var/log/containers/*.log
        Exclude_Path      /var/log/containers/*_kube-system_*,/var/log/containers/*_logging_*
        Parser            docker
        Tag               kube
        Refresh_Interval  5

    [OUTPUT]
        Name            opensearch
        Match           rasp.*
        Host            opensearch
        Port            9200
        Index           rasp-logs
        Type            _doc
        Logstash_Format On
        Logstash_Prefix rasp
        Retry_Limit     5

    [OUTPUT]
        Name            opensearch
        Match           kube
        Host            opensearch
        Port            9200
        Index           kubernetes-logs
        Type            _doc
        Logstash_Format On
        Logstash_Prefix kubernetes
        Retry_Limit     5

  parsers.conf: |
    [PARSER]
        Name        docker
        Format      json
        Time_Key    time
        Time_Format %Y-%m-%dT%H:%M:%S.%L
        Time_Keep   On
EOF
    
    log_success "Fluent Bit deployed"
}

# Wait for deployments
wait_for_deployments() {
    log_info "Waiting for deployments to be ready..."
    
    kubectl wait --for=condition=available deployment/opensearch -n $NAMESPACE --timeout=300s
    kubectl wait --for=condition=available deployment/opensearch-dashboards -n $NAMESPACE --timeout=300s
    
    log_success "All deployments ready"
}

# Show access information
show_access_info() {
    NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
    
    echo ""
    log_success "🎉 Simple RASP logging stack deployed successfully!"
    echo ""
    echo "📊 Access URLs:"
    echo "➡️  OpenSearch Dashboards: http://$NODE_IP:30001"
    echo ""
    echo "🔍 To create index patterns in OpenSearch Dashboards:"
    echo "1. Open the URL above"
    echo "2. Go to Stack Management > Index Patterns"
    echo "3. Create pattern: 'rasp-*' for RASP logs"
    echo "4. Create pattern: 'kubernetes-*' for Kubernetes logs"
    echo ""
    echo "🚀 No authentication required - ready to use!"
}

# Main execution
main() {
    log_info "🚀 Starting simple RASP logging stack deployment..."
    echo ""
    
    create_namespace
    deploy_opensearch
    deploy_opensearch_dashboards
    deploy_simple_fluentbit
    wait_for_deployments
    show_access_info
    
    log_success "✅ Deployment completed!"
}

main "$@" 