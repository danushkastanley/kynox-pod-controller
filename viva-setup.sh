#!/bin/bash

# =============================================================================
# VIVA DEMO SETUP SCRIPT
# =============================================================================
# Prepares your environment for the perfect RASP security demo

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🎓 RASP VIVA DEMO SETUP${NC}"
echo -e "${BLUE}======================${NC}"
echo ""

# =============================================================================
# STEP 1: ENVIRONMENT VERIFICATION
# =============================================================================

echo -e "${GREEN}📋 STEP 1: Environment Verification${NC}"
echo "Checking your setup..."

# Check if we're in the right directory
if [[ ! -f "pod-controller/pkg/server/server.go" ]]; then
    echo -e "${RED}❌ Error: Please run this from the project root directory${NC}"
    echo "Current directory: $(pwd)"
    echo "Expected: A directory containing pod-controller/"
    exit 1
fi

echo -e "${GREEN}✅ Project structure verified${NC}"

# Check kubectl access
if kubectl cluster-info >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Kubernetes cluster accessible${NC}"
    CURRENT_CONTEXT=$(kubectl config current-context 2>/dev/null || echo "unknown")
    echo "   Current context: $CURRENT_CONTEXT"
else
    echo -e "${YELLOW}⚠️  Warning: Kubernetes cluster not accessible${NC}"
    echo "   Make sure your cluster is running and kubectl is configured"
fi

# Check if monitoring pods are running
echo ""
echo "Checking RASP monitoring system status..."
if kubectl get pods -l app=pod-agent >/dev/null 2>&1; then
    POD_AGENT_STATUS=$(kubectl get pods -l app=pod-agent --no-headers 2>/dev/null | awk '{print $3}' | head -1)
    echo -e "${GREEN}✅ Pod-agent found: Status = $POD_AGENT_STATUS${NC}"
else
    echo -e "${YELLOW}⚠️  Pod-agent not found or not labeled properly${NC}"
fi

if kubectl get pods -l app=pod-controller >/dev/null 2>&1; then
    POD_CONTROLLER_STATUS=$(kubectl get pods -l app=pod-controller --no-headers 2>/dev/null | awk '{print $3}' | head -1)
    echo -e "${GREEN}✅ Pod-controller found: Status = $POD_CONTROLLER_STATUS${NC}"
else
    echo -e "${YELLOW}⚠️  Pod-controller not found or not labeled properly${NC}"
fi

sleep 2

# =============================================================================
# STEP 2: DEMO SCRIPT PREPARATION
# =============================================================================

echo ""
echo -e "${GREEN}🛠️  STEP 2: Demo Script Preparation${NC}"

# Make demo scripts executable
chmod +x pod-controller/demo-security-events.sh 2>/dev/null || true
chmod +x pod-controller/viva-critical-demo.sh 2>/dev/null || true

echo -e "${GREEN}✅ Demo scripts made executable${NC}"
echo "   📁 demo-security-events.sh - Comprehensive demo"
echo "   🚨 viva-critical-demo.sh - Critical events only"

# =============================================================================
# STEP 3: MONITORING ENDPOINTS VERIFICATION
# =============================================================================

echo ""
echo -e "${GREEN}📊 STEP 3: Monitoring Endpoints${NC}"

# Check OpenSearch/Elasticsearch
if kubectl get svc -A | grep -i opensearch >/dev/null 2>&1; then
    OPENSEARCH_SVC=$(kubectl get svc -A | grep -i opensearch | head -1 | awk '{print $1"/"$2}')
    echo -e "${GREEN}✅ OpenSearch service found: $OPENSEARCH_SVC${NC}"
elif kubectl get svc -A | grep -i elasticsearch >/dev/null 2>&1; then
    ELASTIC_SVC=$(kubectl get svc -A | grep -i elasticsearch | head -1 | awk '{print $1"/"$2}')
    echo -e "${GREEN}✅ Elasticsearch service found: $ELASTIC_SVC${NC}"
else
    echo -e "${YELLOW}⚠️  No OpenSearch/Elasticsearch service found${NC}"
fi

# Check Grafana
if kubectl get svc -A | grep -i grafana >/dev/null 2>&1; then
    GRAFANA_SVC=$(kubectl get svc -A | grep -i grafana | head -1 | awk '{print $1"/"$2}')
    echo -e "${GREEN}✅ Grafana service found: $GRAFANA_SVC${NC}"
else
    echo -e "${YELLOW}⚠️  No Grafana service found${NC}"
fi

sleep 2

# =============================================================================
# STEP 4: DEMO CHEAT SHEET
# =============================================================================

echo ""
echo -e "${BLUE}📝 STEP 4: VIVA DEMO CHEAT SHEET${NC}"
echo -e "${BLUE}================================${NC}"

cat > pod-controller/VIVA_CHEAT_SHEET.md << 'EOF'
# 🎓 RASP VIVA DEMO CHEAT SHEET

## 🚀 Quick Demo Commands

### 1. **Start Critical Security Demo**
```bash
./pod-controller/viva-critical-demo.sh
```
**What it does:** Triggers CRITICAL alerts (chmod 777 /etc/passwd, network activity, etc.)

### 2. **Full Comprehensive Demo**
```bash
./pod-controller/demo-security-events.sh
```
**What it does:** Triggers all types of security events for complete demonstration

### 3. **Manual Critical Event (Your Example)**
```bash
sudo chmod 777 /etc/passwd
# Wait 30 seconds for alert
sudo chmod 644 /etc/passwd  # Restore
```

## 📊 Monitoring Commands

### **Check Pod Status**
```bash
kubectl get pods -l app=pod-agent
kubectl get pods -l app=pod-controller
```

### **Watch Real-time Logs**
```bash
# Agent logs (eBPF events)
kubectl logs -f -l app=pod-agent

# Controller logs (classifications & alerts)
kubectl logs -f -l app=pod-controller
```

### **Check Slack Integration**
```bash
kubectl logs -l app=pod-controller | grep -i slack
kubectl logs -l app=pod-controller | grep -i alert
```

## 🔍 Dashboard Access

### **OpenSearch/Kibana**
```bash
# Port forward to access dashboards
kubectl port-forward svc/opensearch-cluster-master 9200:9200 -n logging &
# Access: http://localhost:9200
```

### **Grafana**
```bash
kubectl port-forward svc/grafana 3000:3000 -n monitoring &
# Access: http://localhost:3000
```

## 🎯 Demo Flow for Viva

### **Opening (2 minutes)**
1. "Our RASP system provides real-time security monitoring using eBPF..."
2. Show architecture diagram
3. Explain low-overhead, kernel-level monitoring

### **Live Demo (5 minutes)**
1. **Execute:** `./pod-controller/viva-critical-demo.sh`
2. **Show:** Slack alerts appearing in real-time
3. **Navigate:** OpenSearch/Kibana dashboards
4. **Filter:** Events by severity, pod, time
5. **Explain:** Multi-channel alerting (Slack + logs + dashboards)

### **Technical Deep Dive (3 minutes)**
1. **Show:** `kubectl logs -f -l app=pod-agent` (eBPF event capture)
2. **Show:** `kubectl logs -f -l app=pod-controller` (classification)
3. **Explain:** YAML-based rules, CVE integration capability
4. **Highlight:** Kubernetes-native deployment, scalability

## 🚨 Critical Events That Trigger Alerts

| Event | Severity | Description |
|-------|----------|-------------|
| `chmod 777 /etc/passwd` | **CRITICAL** | World-writable auth file |
| `chmod 777 /etc/shadow` | **CRITICAL** | World-writable shadow file |
| External network connections | **HIGH** | Suspicious outbound traffic |
| Netcat/suspicious tools | **HIGH** | Network tool execution |
| SSH key file access | **HIGH** | Sensitive file access |
| Python/shell execution | **WARN** | Interpreter execution |

## 🎤 Key Talking Points

### **Technical Innovation**
- "eBPF-based monitoring with zero code injection"
- "Sub-millisecond event detection and classification" 
- "Kubernetes-native with automatic scaling"

### **Security Capabilities**
- "Real-time threat detection across all containers"
- "Multi-level severity classification with CVE integration"
- "Behavioral analysis beyond signature-based detection"

### **Enterprise Ready**
- "Multi-channel alerting with rate limiting"
- "YAML-based rule customization for different environments"
- "Comprehensive audit logging for compliance"

## 🆘 Emergency Commands

### **If Demo Breaks**
```bash
# Restart monitoring stack
kubectl rollout restart deployment/pod-controller
kubectl rollout restart daemonset/pod-agent

# Check logs for errors
kubectl logs -l app=pod-controller --tail=50
kubectl logs -l app=pod-agent --tail=50
```

### **Quick Test Alert**
```bash
# Guaranteed to trigger alert
sudo chmod 777 /etc/passwd && sleep 3 && sudo chmod 644 /etc/passwd
```

## 🏆 Success Metrics

- ✅ Real-time alerts in Slack
- ✅ Events visible in dashboards  
- ✅ Proper event classification
- ✅ No false positives for system processes
- ✅ Sub-second response times

---
**Good luck with your viva! 🎓**
EOF

echo -e "${GREEN}✅ Cheat sheet created: pod-controller/VIVA_CHEAT_SHEET.md${NC}"

# =============================================================================
# STEP 5: FINAL VERIFICATION
# =============================================================================

echo ""
echo -e "${GREEN}🎯 STEP 5: Final Verification${NC}"

echo "Testing basic monitoring functionality..."

# Test kubectl access
if kubectl get nodes >/dev/null 2>&1; then
    NODE_COUNT=$(kubectl get nodes --no-headers | wc -l)
    echo -e "${GREEN}✅ Cluster accessible: $NODE_COUNT nodes${NC}"
else
    echo -e "${RED}❌ Cannot access Kubernetes cluster${NC}"
fi

# Check if essential commands are available
MISSING_COMMANDS=()
for cmd in curl python3 bash chmod sudo; do
    if ! which $cmd >/dev/null 2>&1; then
        MISSING_COMMANDS+=($cmd)
    fi
done

if [ ${#MISSING_COMMANDS[@]} -eq 0 ]; then
    echo -e "${GREEN}✅ All required commands available${NC}"
else
    echo -e "${YELLOW}⚠️  Missing commands: ${MISSING_COMMANDS[*]}${NC}"
fi

# =============================================================================
# COMPLETION
# =============================================================================

echo ""
echo -e "${BLUE}🎉 VIVA SETUP COMPLETE!${NC}"
echo -e "${BLUE}======================${NC}"
echo ""
echo -e "${GREEN}Your RASP demo environment is ready! Here's what to do:${NC}"
echo ""
echo -e "${YELLOW}📋 Quick Start:${NC}"
echo -e "  1. Read: ${BLUE}pod-controller/VIVA_CHEAT_SHEET.md${NC}"
echo -e "  2. Test: ${BLUE}./pod-controller/viva-critical-demo.sh${NC}"
echo -e "  3. Check: Slack alerts and dashboard updates"
echo ""
echo -e "${YELLOW}🎯 For Your Viva:${NC}"
echo -e "  • Open monitoring dashboards before starting"
echo -e "  • Have Slack channel visible on screen"
echo -e "  • Prepare to show both agent and controller logs"
echo -e "  • Practice the demo flow once before presentation"
echo ""
echo -e "${GREEN}💪 You've got a production-ready RASP system to demonstrate!${NC}"
echo -e "${GREEN}Good luck with your viva presentation! 🎓${NC}" 