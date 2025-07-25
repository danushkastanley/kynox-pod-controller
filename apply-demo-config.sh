#!/bin/bash

# =============================================================================
# Apply Demo Configuration with Filtered Alerts
# =============================================================================
# This script applies the demo configuration that only alerts on critical events

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🎯 Applying Demo Alert Configuration${NC}"
echo -e "${BLUE}===================================${NC}"
echo ""

# Check if we're in the right directory
if [[ ! -f "pod-controller/demo.env" ]]; then
    echo -e "${RED}❌ Error: Please run this from the project root directory${NC}"
    echo "Current directory: $(pwd)"
    exit 1
fi

echo -e "${GREEN}📋 Current Alert Configuration:${NC}"
echo -e "${YELLOW}Event Types:${NC} SETUID,PTRACE,BPF_PROG,MOUNT,SECCOMP,CHMOD,OPEN"
echo -e "${YELLOW}Min Level:${NC} warning"
echo -e "${YELLOW}Rate Limit:${NC} 10 alerts/minute"
echo ""

echo -e "${GREEN}🎯 This configuration will alert on:${NC}"
echo -e "  🚨 CHMOD - File permission changes (chmod 777 /etc/passwd)"
echo -e "  🚨 SETUID - Privilege escalation attempts"  
echo -e "  🚨 OPEN - Sensitive file access (/etc/shadow, /etc/ssh/)"
echo -e "  🚨 MOUNT - Filesystem mount operations"
echo -e "  🚨 PTRACE - Process debugging attempts"
echo -e "  🚨 BPF_PROG - eBPF program loading"
echo -e "  🚨 SECCOMP - Security mechanism changes"
echo ""

echo -e "${GREEN}🚫 This configuration will NOT alert on:${NC}"
echo -e "  ❌ EXEC - Process execution (too noisy)"
echo -e "  ❌ CONNECT - Network connections (too noisy)"
echo -e "  ❌ BIND - Socket binding (too noisy)"
echo -e "  ❌ ACCEPT - Connection acceptance (too noisy)"
echo ""

read -p "Apply this configuration? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Configuration not applied.${NC}"
    exit 0
fi

echo ""
echo -e "${GREEN}🔧 Applying Configuration...${NC}"

# Apply the updated Kubernetes ConfigMap
echo "Applying Kubernetes ConfigMap..."
kubectl apply -f pod-controller/deployments/pod-controller-config.yaml

# Check if pod-controller is running and restart it to pick up new config
if kubectl get deployment pod-controller >/dev/null 2>&1; then
    echo "Restarting pod-controller to pick up new configuration..."
    kubectl rollout restart deployment/pod-controller
    
    echo "Waiting for rollout to complete..."
    kubectl rollout status deployment/pod-controller --timeout=60s
    
    echo -e "${GREEN}✅ Pod-controller restarted with new configuration${NC}"
else
    echo -e "${YELLOW}⚠️  Pod-controller deployment not found, please deploy it manually${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Demo Configuration Applied Successfully!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Wait 30 seconds for configuration to take effect"
echo -e "  2. Run: ${BLUE}./pod-controller/viva-critical-demo.sh${NC}"
echo -e "  3. Check: Slack alerts (should see fewer, higher-quality alerts)"
echo -e "  4. Verify: Only critical security events trigger notifications"
echo ""

echo -e "${GREEN}📊 Monitor the results:${NC}"
echo -e "  💬 Slack channel: Only critical events"
echo -e "  📋 Controller logs: ${BLUE}kubectl logs -f -l app=pod-controller${NC}"
echo -e "  🔍 Event filtering: Check logs for 'Skipping alert - event type X not configured'"
echo ""

echo -e "${BLUE}Your demo will now show focused, high-impact security alerts! 🎯${NC}" 