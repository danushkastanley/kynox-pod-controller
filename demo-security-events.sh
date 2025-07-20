#!/bin/bash

# =============================================================================
# RASP Security Monitoring Demo Script
# =============================================================================
# This script triggers various security events to demonstrate the RASP system
# Perfect for viva presentations and security demonstrations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛡️  RASP Security Monitoring Demo${NC}"
echo -e "${BLUE}====================================${NC}"
echo ""
echo -e "${GREEN}This script will trigger various security events to demonstrate:"
echo -e "  🚨 Critical security alerts"
echo -e "  ⚠️  High severity events"
echo -e "  📡 Network monitoring"
echo -e "  📁 File access monitoring"
echo -e "  🔐 Permission changes"
echo -e "  💬 Slack integration${NC}"
echo ""

# Wait for user confirmation
read -p "Press Enter to continue or Ctrl+C to cancel..."
echo ""

# =============================================================================
# PHASE 1: CRITICAL SECURITY EVENTS
# =============================================================================

echo -e "${RED}🚨 PHASE 1: CRITICAL SECURITY EVENTS${NC}"
echo -e "${RED}=====================================${NC}"

echo -e "${YELLOW}1. Dangerous File Permission Changes${NC}"
echo "   Triggering: chmod 777 /etc/passwd (CRITICAL ALERT Expected)"
sleep 2

# Create a backup first
sudo cp /etc/passwd /etc/passwd.backup.demo 2>/dev/null || true

# This should trigger a CRITICAL alert
sudo chmod 777 /etc/passwd
echo -e "${GREEN}   ✅ Triggered: World-writable permissions on sensitive file${NC}"
sleep 3

# Restore permissions
sudo chmod 644 /etc/passwd
echo -e "${GREEN}   ↩️  Restored: Original permissions${NC}"
sleep 2

echo -e "${YELLOW}2. Suspicious Command Execution${NC}"
echo "   Triggering: netcat execution (HIGH/CRITICAL ALERT Expected)"
sleep 2

# Try different suspicious commands
echo "   Testing network tools..."
which nc >/dev/null 2>&1 && {
    echo "Testing netcat connection..." | nc -l -p 31337 -w 1 &
    sleep 1
    pkill nc 2>/dev/null || true
    echo -e "${GREEN}   ✅ Triggered: Netcat execution${NC}"
} || echo -e "${YELLOW}   ⚠️  Netcat not available${NC}"

# Python reverse shell attempt (will fail but should trigger alert)
echo "   Testing suspicious Python execution..."
python3 -c "print('Simulated suspicious command')" 2>/dev/null || true
echo -e "${GREEN}   ✅ Triggered: Python execution${NC}"
sleep 2

echo -e "${YELLOW}3. Sensitive File Access${NC}"
echo "   Triggering: SSH key access (HIGH ALERT Expected)"
sleep 2

# Access SSH keys (read-only, safe)
sudo cat /etc/ssh/sshd_config | head -5 >/dev/null 2>&1 || true
echo -e "${GREEN}   ✅ Triggered: SSH configuration access${NC}"

# Try to access shadow file
sudo ls -la /etc/shadow >/dev/null 2>&1 || true
echo -e "${GREEN}   ✅ Triggered: Password shadow file access${NC}"
sleep 2

# =============================================================================
# PHASE 2: NETWORK MONITORING
# =============================================================================

echo ""
echo -e "${PURPLE}📡 PHASE 2: NETWORK MONITORING${NC}"
echo -e "${PURPLE}===============================${NC}"

echo -e "${YELLOW}4. External Network Connections${NC}"
echo "   Triggering: External IP connections (WARN/HIGH ALERT Expected)"
sleep 2

# Test external connections (safe - just connection attempts)
echo "   Testing external HTTP connection..."
curl -m 5 --connect-timeout 5 http://httpbin.org/ip >/dev/null 2>&1 || true
echo -e "${GREEN}   ✅ Triggered: External HTTP connection${NC}"

echo "   Testing DNS resolution..."
nslookup google.com >/dev/null 2>&1 || true
echo -e "${GREEN}   ✅ Triggered: DNS query${NC}"

echo "   Testing suspicious port access..."
# Try to connect to common suspicious ports
timeout 3 bash -c 'echo >/dev/tcp/8.8.8.8/22' 2>/dev/null || true
echo -e "${GREEN}   ✅ Triggered: SSH port connection attempt${NC}"
sleep 2

# =============================================================================
# PHASE 3: PROCESS AND SYSTEM MONITORING  
# =============================================================================

echo ""
echo -e "${BLUE}🔍 PHASE 3: PROCESS AND SYSTEM MONITORING${NC}"
echo -e "${BLUE}=========================================${NC}"

echo -e "${YELLOW}5. Process Execution Monitoring${NC}"
echo "   Triggering: Shell spawning and interpreters"
sleep 2

# Spawn various interpreters
echo "   Testing shell execution..."
bash -c 'echo "Shell command execution test"' >/dev/null
echo -e "${GREEN}   ✅ Triggered: Bash execution${NC}"

echo "   Testing script interpreter..."
which python3 >/dev/null && python3 -c "import os; print('Python execution test')" >/dev/null 2>&1 || true
echo -e "${GREEN}   ✅ Triggered: Python interpreter${NC}"

which node >/dev/null && echo "console.log('Node test')" | node >/dev/null 2>&1 || echo -e "${YELLOW}   ⚠️  Node.js not available${NC}"

sleep 2

echo -e "${YELLOW}6. File System Monitoring${NC}"
echo "   Triggering: Various file operations"
sleep 2

# Create temp files and modify permissions
TMP_FILE="/tmp/demo_security_test_$$"
echo "Test file for security demo" > "$TMP_FILE"

echo "   Testing file permission changes..."
chmod 755 "$TMP_FILE"
chmod 644 "$TMP_FILE"
echo -e "${GREEN}   ✅ Triggered: File permission modifications${NC}"

echo "   Testing file access patterns..."
cat "$TMP_FILE" >/dev/null
ls -la "$TMP_FILE" >/dev/null
echo -e "${GREEN}   ✅ Triggered: File access operations${NC}"

# Cleanup
rm -f "$TMP_FILE"
sleep 2

# =============================================================================
# PHASE 4: CONTAINER AND KUBERNETES SPECIFIC
# =============================================================================

echo ""
echo -e "${GREEN}🐳 PHASE 4: CONTAINER MONITORING${NC}"
echo -e "${GREEN}================================${NC}"

echo -e "${YELLOW}7. Container Runtime Operations${NC}"
echo "   Triggering: Container-related commands"
sleep 2

# Test container commands if available
echo "   Testing container tools..."
which docker >/dev/null 2>&1 && {
    docker --version >/dev/null 2>&1 || true
    echo -e "${GREEN}   ✅ Triggered: Docker command execution${NC}"
} || echo -e "${YELLOW}   ⚠️  Docker not available${NC}"

which kubectl >/dev/null 2>&1 && {
    kubectl version --client >/dev/null 2>&1 || true
    echo -e "${GREEN}   ✅ Triggered: Kubectl execution${NC}"
} || echo -e "${YELLOW}   ⚠️  Kubectl not available${NC}"

# Check for kubernetes files
echo "   Testing Kubernetes file access..."
ls /var/run/secrets/kubernetes.io/ >/dev/null 2>&1 && {
    echo -e "${GREEN}   ✅ Triggered: Kubernetes secrets access${NC}"
} || echo -e "${YELLOW}   ℹ️  No Kubernetes secrets found${NC}"

sleep 2

# =============================================================================
# FINAL PHASE: SUMMARY AND VERIFICATION
# =============================================================================

echo ""
echo -e "${BLUE}📊 DEMO COMPLETE - VERIFICATION${NC}"
echo -e "${BLUE}===============================${NC}"

echo -e "${GREEN}✅ Demo script completed successfully!"
echo ""
echo -e "${YELLOW}Expected Alerts Generated:${NC}"
echo -e "  🚨 CRITICAL: chmod 777 /etc/passwd"
echo -e "  🚨 CRITICAL/HIGH: Suspicious command executions"
echo -e "  ⚠️  HIGH: Sensitive file access (/etc/shadow, /etc/ssh/)"
echo -e "  ⚠️  WARN/HIGH: External network connections"
echo -e "  ℹ️  Various: Process executions and file operations"
echo ""
echo -e "${GREEN}Next Steps for Your Viva:${NC}"
echo -e "  1. 💬 Check your Slack channel for security alerts"
echo -e "  2. 📊 Open Kibana/OpenSearch dashboards" 
echo -e "  3. 🔍 Show real-time event filtering and search"
echo -e "  4. 📈 Demonstrate alert aggregation and rate limiting"
echo -e "  5. 🛡️  Explain the different severity levels"
echo ""
echo -e "${PURPLE}🎯 Pro Tips for Demo:${NC}"
echo -e "  • Run this script in a monitored pod/container"
echo -e "  • Show both agent logs and controller logs"
echo -e "  • Demonstrate rule customization capabilities"
echo -e "  • Highlight the low-overhead eBPF monitoring"
echo -e "  • Explain the Kubernetes-native deployment"
echo ""
echo -e "${GREEN}🎉 Good luck with your viva presentation!${NC}"

# Cleanup any demo artifacts
sudo rm -f /etc/passwd.backup.demo 2>/dev/null || true

echo ""
echo -e "${BLUE}Demo script finished. Check your monitoring systems now!${NC}" 