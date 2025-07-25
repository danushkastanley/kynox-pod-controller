#!/bin/bash

# Complete RASP Logging Stack Deployment Script
# This script deploys OpenSearch with persistent storage and FluentBit for complete log collection

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== RASP Complete Logging Stack Deployment ===${NC}"
echo -e "${YELLOW}This script will deploy OpenSearch + FluentBit with persistent storage${NC}"
echo ""

# Configuration
NAMESPACE=logging
DATABASE_NAMESPACE=database
STORAGE_BASE="/data"

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        print_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    print_status "Prerequisites check passed"
}

# Create storage directories
setup_storage() {
    print_status "Setting up storage directories..."
    
    if [ ! -d "$STORAGE_BASE" ]; then
        print_warning "Creating $STORAGE_BASE directory. You might need sudo privileges."
        sudo mkdir -p "$STORAGE_BASE/opensearch"
        sudo chmod 755 "$STORAGE_BASE"
        sudo chmod 755 "$STORAGE_BASE/opensearch"
        sudo chown 1000:1000 "$STORAGE_BASE/opensearch"  # OpenSearch UID
    else
        print_status "Storage base directory already exists"
        if [ ! -d "$STORAGE_BASE/opensearch" ]; then
            sudo mkdir -p "$STORAGE_BASE/opensearch"
            sudo chmod 755 "$STORAGE_BASE/opensearch"
            sudo chown 1000:1000 "$STORAGE_BASE/opensearch"
        fi
    fi
}

# Deploy OpenSearch with persistent storage
deploy_opensearch() {
    print_status "Deploying OpenSearch with persistent storage..."
    
    cat <<EOF | kubectl apply -f -
# OpenSearch with Persistent Storage Configuration
apiVersion: v1
kind: Namespace
metadata:
  name: $NAMESPACE
---
# PersistentVolume for OpenSearch data
apiVersion: v1
kind: PersistentVolume
metadata:
  name: opensearch-pv
spec:
  capacity:
    storage: 20Gi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: manual
  hostPath:
    path: $STORAGE_BASE/opensearch
    type: DirectoryOrCreate
---
# PersistentVolumeClaim for OpenSearch
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: opensearch-pvc
  namespace: $NAMESPACE
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 20Gi
  storageClassName: manual
---
# OpenSearch StatefulSet
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: opensearch
  namespace: $NAMESPACE
spec:
  serviceName: opensearch-headless
  replicas: 1
  selector:
    matchLabels:
      app: opensearch
  template:
    metadata:
      labels:
        app: opensearch
    spec:
      securityContext:
        fsGroup: 1000
      initContainers:
      - name: increase-vm-max-map
        image: busybox:1.28
        securityContext:
          privileged: true
        command:
        - sysctl
        - -w
        - vm.max_map_count=262144
      containers:
      - name: opensearch
        image: opensearchproject/opensearch:2.11.0
        env:
        - name: cluster.name
          value: "opensearch-cluster"
        - name: node.name
          value: "opensearch-node1"
        - name: discovery.type
          value: single-node
        - name: OPENSEARCH_JAVA_OPTS
          value: "-Xms2g -Xmx2g"
        - name: DISABLE_SECURITY_PLUGIN
          value: "true"
        - name: DISABLE_INSTALL_DEMO_CONFIG
          value: "true"
        - name: bootstrap.memory_lock
          value: "true"
        ports:
        - name: http
          containerPort: 9200
        - name: transport
          containerPort: 9300
        volumeMounts:
        - name: opensearch-data
          mountPath: /usr/share/opensearch/data
        resources:
          requests:
            memory: "3Gi"
            cpu: "1000m"
          limits:
            memory: "6Gi"
            cpu: "2000m"
        readinessProbe:
          httpGet:
            path: /_cluster/health
            port: 9200
          initialDelaySeconds: 30
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /_cluster/health
            port: 9200
          initialDelaySeconds: 60
          periodSeconds: 30
      volumes:
      - name: opensearch-data
        persistentVolumeClaim:
          claimName: opensearch-pvc
---
# Headless service for StatefulSet
apiVersion: v1
kind: Service
metadata:
  name: opensearch-headless
  namespace: $NAMESPACE
spec:
  clusterIP: None
  selector:
    app: opensearch
  ports:
  - name: http
    port: 9200
    targetPort: 9200
  - name: transport
    port: 9300
    targetPort: 9300
---
# Regular service for external access
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
---
# OpenSearch Dashboards Deployment
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
        - name: SERVER_HOST
          value: "0.0.0.0"
        ports:
        - containerPort: 5601
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        readinessProbe:
          httpGet:
            path: /api/status
            port: 5601
          initialDelaySeconds: 30
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /api/status
            port: 5601
          initialDelaySeconds: 60
          periodSeconds: 30
---
# OpenSearch Dashboards Service
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

    print_status "OpenSearch deployment submitted"
}

# Deploy FluentBit
deploy_fluentbit() {
    print_status "Deploying FluentBit for log collection..."
    
    cat <<EOF | kubectl apply -f -
# FluentBit Configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: $NAMESPACE
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         5
        Grace         30
        Daemon        Off
        Log_Level     info
        Parsers_File  parsers.conf
        HTTP_Server   On
        HTTP_Listen   0.0.0.0
        HTTP_Port     2020
        Health_Check  On

    [INPUT]
        Name              tail
        Tag               rasp.*
        Path              /var/log/containers/*rasp*.log,/var/log/containers/*pod-agent*.log,/var/log/containers/*pod-controller*.log
        Parser            docker
        DB                /var/log/flb_rasp.db
        Mem_Buf_Limit     50MB
        Skip_Long_Lines   On
        Refresh_Interval  10

    [INPUT]
        Name              tail
        Tag               kubernetes.*
        Path              /var/log/containers/*.log
        Exclude_Path      /var/log/containers/*rasp*.log,/var/log/containers/*pod-agent*.log,/var/log/containers/*pod-controller*.log
        Parser            docker
        DB                /var/log/flb_kube.db
        Mem_Buf_Limit     50MB
        Skip_Long_Lines   On
        Refresh_Interval  10

    [FILTER]
        Name                kubernetes
        Match               rasp.*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix     rasp.var.log.containers.
        Merge_Log           On
        Keep_Log            Off
        K8S-Logging.Parser  On
        K8S-Logging.Exclude On
        Annotations         Off
        Labels              On

    [FILTER]
        Name                kubernetes
        Match               kubernetes.*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix     kubernetes.var.log.containers.
        Merge_Log           On
        Keep_Log            Off
        K8S-Logging.Parser  On
        K8S-Logging.Exclude On
        Annotations         Off
        Labels              On

    [FILTER]
        Name          lua
        Match         rasp.*
        script        /fluent-bit/etc/json_parser.lua
        call          parse_json_logs

    [OUTPUT]
        Name            opensearch
        Match           rasp.*
        Host            opensearch.logging.svc.cluster.local
        Port            9200
        Index           rasp
        tls             Off
        tls.verify      Off
        Suppress_Type_Name On
        Logstash_Format On
        Logstash_Prefix rasp
        Logstash_DateFormat %Y.%m.%d
        Include_Tag_Key On
        Tag_Key         source_tag
        Retry_Limit     3
        workers         1
        
    [OUTPUT]
        Name            opensearch
        Match           kubernetes.*
        Host            opensearch.logging.svc.cluster.local
        Port            9200
        Index           kubernetes
        tls             Off
        tls.verify      Off
        Suppress_Type_Name On
        Logstash_Format On
        Logstash_Prefix kubernetes
        Logstash_DateFormat %Y.%m.%d
        Include_Tag_Key On
        Tag_Key         source_tag
        Retry_Limit     3
        workers         1

  parsers.conf: |
    [PARSER]
        Name   docker
        Format json
        Time_Key time
        Time_Format %Y-%m-%dT%H:%M:%S.%L
        Time_Keep   On

    [PARSER]
        Name        json_parser
        Format      json
        Time_Key    timestamp
        Time_Format %Y-%m-%dT%H:%M:%S.%L
        Time_Keep   On

  json_parser.lua: |
    function parse_json_logs(tag, timestamp, record)
        local log = record["log"]
        
        if log and type(log) == "string" then
            -- Check if log starts with '{' (JSON)
            if string.sub(log, 1, 1) == "{" then
                local json = require("cjson")
                local success, parsed = pcall(json.decode, log)
                
                if success and type(parsed) == "table" then
                    -- Successfully parsed JSON - merge fields
                    for key, value in pairs(parsed) do
                        record[key] = value
                    end
                    
                    -- Create easily accessible copies of important fields
                    if parsed.severity then
                        record["level_severity"] = parsed.severity
                    end
                    if parsed.event_type then
                        record["rasp_event_type"] = parsed.event_type
                    end
                    if parsed.agent_id then
                        record["rasp_agent_id"] = parsed.agent_id
                    end
                    if parsed.message then
                        record["rasp_message"] = parsed.message
                    end
                    
                    -- Keep original log for reference
                    record["original_log"] = log
                else
                    -- Not valid JSON - keep as plain text
                    record["log_type"] = "plain_text"
                end
            else
                -- Not JSON - keep as plain text
                record["log_type"] = "plain_text"
            end
        end
        
        return 1, timestamp, record
    end
---
# FluentBit DaemonSet
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluent-bit
  namespace: $NAMESPACE
  labels:
    k8s-app: fluent-bit-logging
    version: v1
    kubernetes.io/cluster-service: "true"
spec:
  selector:
    matchLabels:
      k8s-app: fluent-bit-logging
  template:
    metadata:
      labels:
        k8s-app: fluent-bit-logging
        version: v1
        kubernetes.io/cluster-service: "true"
    spec:
      serviceAccount: fluent-bit
      serviceAccountName: fluent-bit
      tolerations:
        - key: node-role.kubernetes.io/master
          operator: Exists
          effect: NoSchedule
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
        - operator: "Exists"
          effect: "NoExecute"
        - operator: "Exists"
          effect: "NoSchedule"
      containers:
      - name: fluent-bit
        image: fluent/fluent-bit:2.2.0
        imagePullPolicy: Always
        ports:
          - containerPort: 2020
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
        - name: fluent-bit-config
          mountPath: /fluent-bit/etc/
        - name: mnt
          mountPath: /mnt
          readOnly: true
      terminationGracePeriodSeconds: 10
      hostNetwork: false
      dnsPolicy: ClusterFirst
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
      - name: mnt
        hostPath:
          path: /mnt
      - name: fluent-bit-config
        configMap:
          name: fluent-bit-config
---
# ServiceAccount for FluentBit
apiVersion: v1
kind: ServiceAccount
metadata:
  name: fluent-bit
  namespace: $NAMESPACE
---
# ClusterRole for FluentBit
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: fluent-bit-read
rules:
- apiGroups: [""]
  resources:
  - namespaces
  - pods
  verbs: ["get", "list", "watch"]
---
# ClusterRoleBinding for FluentBit
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: fluent-bit-read
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: fluent-bit-read
subjects:
- kind: ServiceAccount
  name: fluent-bit
  namespace: $NAMESPACE
EOF

    print_status "FluentBit deployment submitted"
}

# Wait for deployments to be ready
wait_for_deployments() {
    print_status "Waiting for deployments to be ready..."
    
    print_status "Waiting for OpenSearch..."
    kubectl wait --for=condition=ready --timeout=600s pod -l app=opensearch -n $NAMESPACE
    
    print_status "Waiting for OpenSearch Dashboards..."
    kubectl wait --for=condition=available --timeout=300s deployment/opensearch-dashboards -n $NAMESPACE
    
    print_status "Waiting for FluentBit..."
    kubectl wait --for=condition=ready --timeout=180s pod -l k8s-app=fluent-bit-logging -n $NAMESPACE
    
    print_status "All deployments are ready!"
}

# Display access information
show_access_info() {
    echo ""
    echo -e "${BLUE}=== Access Information ===${NC}"
    
    CLUSTER_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
    OPENSEARCH_NODEPORT=$(kubectl get svc opensearch-dashboards -n $NAMESPACE -o jsonpath='{.spec.ports[0].nodePort}')
    
    echo -e "${GREEN}OpenSearch Dashboards:${NC}"
    echo "  URL: http://$CLUSTER_IP:$OPENSEARCH_NODEPORT"
    echo "  API: http://$CLUSTER_IP:9200"
    echo ""
    
    echo -e "${GREEN}FluentBit Status:${NC}"
    kubectl get pods -n $NAMESPACE -l k8s-app=fluent-bit-logging
    echo ""
    
    echo -e "${GREEN}Storage Information:${NC}"
    echo "  OpenSearch data: $STORAGE_BASE/opensearch"
    echo "  Persistent volumes:"
    kubectl get pv | grep opensearch || echo "    (PV not found - check deployment)"
    echo ""
    
    echo -e "${YELLOW}=== Next Steps ===${NC}"
    echo "1. Access OpenSearch Dashboards to view logs"
    echo "2. Create index patterns for 'rasp-*' and 'kubernetes-*'"
    echo "3. Deploy your RASP agents to start collecting security events"
    echo "4. Use './cleanup-logging.sh' to remove everything when needed"
    echo ""
}

# Test connectivity
test_connectivity() {
    print_status "Testing OpenSearch connectivity..."
    sleep 15
    
    CLUSTER_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
    
    if curl -s "http://$CLUSTER_IP:9200/_cluster/health" | grep -q "cluster_name"; then
        print_status "OpenSearch is responding to API calls ✅"
    else
        print_warning "OpenSearch might still be starting up. Wait a few more minutes."
    fi
}

# PostgreSQL deployment (optional)
deploy_postgresql_optional() {
    echo ""
    read -p "Do you want to deploy PostgreSQL for additional data storage? (y/n): " deploy_postgres
    if [[ $deploy_postgres =~ ^[Yy]$ ]]; then
        print_status "Deploying PostgreSQL..."
        
        # Setup PostgreSQL storage
        if [ ! -d "$STORAGE_BASE/postgresql" ]; then
            sudo mkdir -p "$STORAGE_BASE/postgresql"
            sudo chmod 755 "$STORAGE_BASE/postgresql"
            sudo chown 999:999 "$STORAGE_BASE/postgresql"  # PostgreSQL UID
        fi
        
        kubectl apply -f postgresql-persistent-deploy.yaml
        
        print_status "Waiting for PostgreSQL..."
        kubectl wait --for=condition=ready --timeout=300s pod -l app=postgres -n database
        
        PGADMIN_NODEPORT=$(kubectl get svc pgadmin -n database -o jsonpath='{.spec.ports[0].nodePort}')
        echo ""
        echo -e "${GREEN}PostgreSQL deployed:${NC}"
        echo "  Database: postgres.database.svc.cluster.local:5432"
        echo "  PgAdmin: http://$CLUSTER_IP:$PGADMIN_NODEPORT"
        echo "  Credentials: postgres/secure_password_123"
    fi
}

# Main execution
main() {
    check_prerequisites
    setup_storage
    deploy_opensearch
    deploy_fluentbit
    wait_for_deployments
    test_connectivity
    deploy_postgresql_optional
    show_access_info
    
    print_status "🎉 Complete logging stack deployment finished!"
    echo ""
    print_status "Your RASP monitoring system is ready to collect and analyze security events."
}

# Run main function
main "$@" 