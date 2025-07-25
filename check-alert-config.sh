#!/bin/bash

# =============================================================================
# Check Current Alert Configuration
# =============================================================================
# Shows what events will and won't trigger alerts

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🔍 RASP Alert Configuration Status${NC}"
echo -e "${BLUE}==================================${NC}"
echo ""

# Check Kubernetes ConfigMap
if kubectl get configmap rasp-controller-config >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Kubernetes ConfigMap found${NC}"
    
    # Extract the relevant configuration
    ALERT_EVENT_TYPES=$(kubectl get configmap rasp-controller-config -o jsonpath='{.data.\.env}' | grep ALERT_EVENT_TYPES | cut -d'=' -f2)
    ALERT_MIN_LEVEL=$(kubectl get configmap rasp-controller-config -o jsonpath='{.data.\.env}' | grep ALERT_MIN_LEVEL | cut -d'=' -f2)
    ALERT_RATE_LIMIT=$(kubectl get configmap rasp-controller-config -o jsonpath='{.data.\.env}' | grep ALERT_RATE_LIMIT | cut -d'=' -f2)
    
    echo -e "${YELLOW}Current Configuration:${NC}"
    echo -e "  📋 Event Types: ${GREEN}$ALERT_EVENT_TYPES${NC}"
    echo -e "  📊 Min Level: ${GREEN}$ALERT_MIN_LEVEL${NC}"
    echo -e "  ⏱️  Rate Limit: ${GREEN}$ALERT_RATE_LIMIT${NC} alerts/minute"
    echo ""
    
    # Parse and explain event types
    if [[ "$ALERT_EVENT_TYPES" == *"CHMOD"* ]]; then
        echo -e "${GREEN}✅ CHMOD events will trigger alerts${NC}"
        echo -e "   👉 chmod 777 /etc/passwd → Alert!"
    else
        echo -e "${RED}❌ CHMOD events will NOT trigger alerts${NC}"
    fi
    
    if [[ "$ALERT_EVENT_TYPES" == *"SETUID"* ]]; then
        echo -e "${GREEN}✅ SETUID events will trigger alerts${NC}"
        echo -e "   👉 Privilege escalation → Alert!"
    else
        echo -e "${RED}❌ SETUID events will NOT trigger alerts${NC}"
    fi
    
    if [[ "$ALERT_EVENT_TYPES" == *"OPEN"* ]]; then
        echo -e "${GREEN}✅ OPEN events will trigger alerts${NC}"
        echo -e "   👉 /etc/shadow access → Alert!"
    else
        echo -e "${RED}❌ OPEN events will NOT trigger alerts${NC}"
    fi
    
    if [[ "$ALERT_EVENT_TYPES" == *"EXEC"* ]]; then
        echo -e "${YELLOW}⚠️  EXEC events will trigger alerts (may be noisy)${NC}"
    else
        echo -e "${GREEN}✅ EXEC events filtered out (good for demo)${NC}"
    fi
    
    if [[ "$ALERT_EVENT_TYPES" == *"CONNECT"* ]]; then
        echo -e "${YELLOW}⚠️  CONNECT events will trigger alerts (may be noisy)${NC}"
    else
        echo -e "${GREEN}✅ CONNECT events filtered out (good for demo)${NC}"
    fi
    
else
    echo -e "${RED}❌ Kubernetes ConfigMap not found${NC}"
    echo "Run: kubectl apply -f pod-controller/deployments/pod-controller-config.yaml"
fi

echo ""

# Check pod-controller status
if kubectl get pods -l app=pod-controller >/dev/null 2>&1; then
    POD_STATUS=$(kubectl get pods -l app=pod-controller --no-headers | awk '{print $3}' | head -1)
    echo -e "${GREEN}✅ Pod-controller status: $POD_STATUS${NC}"
    
    if [[ "$POD_STATUS" == "Running" ]]; then
        echo -e "${GREEN}📋 Recent controller logs:${NC}"
        kubectl logs -l app=pod-controller --tail=5 | grep -E "(Alert|alert|dispatch|filter)" || echo "   No alert-related logs found"
    fi
else
    echo -e "${RED}❌ Pod-controller not found${NC}"
fi

echo ""
echo -e "${BLUE}🎯 Demo Impact Analysis:${NC}"
echo -e "${BLUE}========================${NC}"

# Simulate what demo commands will do
echo -e "${YELLOW}Demo Command: sudo chmod 777 /etc/passwd${NC}"
if [[ "$ALERT_EVENT_TYPES" == *"CHMOD"* ]]; then
    echo -e "  Result: ${GREEN}🚨 ALERT WILL BE GENERATED${NC}"
    echo -e "  Why: CHMOD event on sensitive file"
    echo -e "  Severity: CRITICAL (world-writable authentication file)"
else
    echo -e "  Result: ${RED}❌ NO ALERT (CHMOD not in event types)${NC}"
fi

echo ""
echo -e "${YELLOW}Demo Command: External network connection${NC}"
if [[ "$ALERT_EVENT_TYPES" == *"CONNECT"* ]]; then
    echo -e "  Result: ${GREEN}🚨 ALERT WILL BE GENERATED${NC}"
else
    echo -e "  Result: ${RED}❌ NO ALERT (CONNECT not in event types)${NC}"
fi

echo ""
echo -e "${YELLOW}Demo Command: SSH file access${NC}"
if [[ "$ALERT_EVENT_TYPES" == *"OPEN"* ]]; then
    echo -e "  Result: ${GREEN}🚨 ALERT WILL BE GENERATED${NC}"
    echo -e "  Why: OPEN event on sensitive file (/etc/ssh/sshd_config)"
else
    echo -e "  Result: ${RED}❌ NO ALERT (OPEN not in event types)${NC}"
fi

echo ""
echo -e "${GREEN}📝 Recommendations:${NC}"
echo -e "  • Ensure CHMOD is in ALERT_EVENT_TYPES for your main demo"
echo -e "  • Include OPEN for sensitive file access alerts"
echo -e "  • Exclude EXEC/CONNECT to reduce noise"
echo -e "  • Set ALERT_MIN_LEVEL to 'warning' to catch more events"
echo ""
echo -e "${BLUE}🔧 To apply the recommended configuration:${NC}"
echo -e "  ${GREEN}./pod-controller/apply-demo-config.sh${NC}" 