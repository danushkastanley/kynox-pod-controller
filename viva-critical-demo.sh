#!/bin/bash

# =============================================================================
# VIVA CRITICAL SECURITY DEMO
# =============================================================================
# Focused script for demonstrating CRITICAL security alerts during viva
# This script triggers only the highest-impact events for maximum effect

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}🚨 CRITICAL SECURITY EVENT DEMO${NC}"
echo -e "${RED}===============================${NC}"
echo ""
echo -e "${YELLOW}This will trigger CRITICAL alerts for your viva demonstration:${NC}"
echo -e "  💥 chmod 777 /etc/passwd (World-writable password file)"
echo -e "  🔓 chmod 777 /etc/shadow (World-writable shadow file)" 
echo -e "  🌐 Root process external network connection"
echo -e "  🐚 Suspicious shell executions"
echo ""

read -p "Press Enter to start the CRITICAL security demo..."
echo ""

# =============================================================================
# CRITICAL EVENT 1: WORLD-WRITABLE PASSWORD FILES
# =============================================================================

echo -e "${RED}🚨 CRITICAL EVENT 1: Dangerous File Permissions${NC}"
echo "Making /etc/passwd world-writable..."
sleep 2

# Backup and modify /etc/passwd
sudo cp /etc/passwd /etc/passwd.viva.backup
sudo chmod 777 /etc/passwd
echo -e "${GREEN}✅ TRIGGERED: chmod 777 /etc/passwd${NC}"
echo "   Expected: CRITICAL alert - World-writable authentication file"
sleep 3

# Backup and modify /etc/shadow  
sudo cp /etc/shadow /etc/shadow.viva.backup 2>/dev/null || true
sudo chmod 777 /etc/shadow 2>/dev/null || true
echo -e "${GREEN}✅ TRIGGERED: chmod 777 /etc/shadow${NC}"
echo "   Expected: CRITICAL alert - World-writable password shadow file"
sleep 3

# Restore original permissions
sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow 2>/dev/null || true
echo -e "${BLUE}↩️  Restored original permissions${NC}"
sleep 2

# =============================================================================
# CRITICAL EVENT 2: SUSPICIOUS NETWORK ACTIVITY
# =============================================================================

echo ""
echo -e "${RED}🚨 CRITICAL EVENT 2: Suspicious Network Activity${NC}"
echo "Triggering external network connections..."
sleep 2

# External connection attempts
echo "Testing external HTTP connection..."
curl -m 3 --connect-timeout 3 http://httpbin.org/ip >/dev/null 2>&1 || true
echo -e "${GREEN}✅ TRIGGERED: External network connection${NC}"
echo "   Expected: WARN/HIGH alert - External IP connection"

echo "Testing suspicious port connection..."
timeout 2 bash -c 'echo >/dev/tcp/8.8.8.8/22' 2>/dev/null || true
echo -e "${GREEN}✅ TRIGGERED: SSH port connection attempt${NC}"
echo "   Expected: HIGH alert - Suspicious port access"
sleep 3

# =============================================================================
# CRITICAL EVENT 3: SUSPICIOUS COMMAND EXECUTION
# =============================================================================

echo ""
echo -e "${RED}🚨 CRITICAL EVENT 3: Suspicious Commands${NC}"
echo "Executing suspicious network tools..."
sleep 2

# Test netcat if available
if which nc >/dev/null 2>&1; then
    echo "Executing netcat..."
    echo "test" | nc -l -p 31338 -w 1 &
    sleep 1
    pkill nc 2>/dev/null || true
    echo -e "${GREEN}✅ TRIGGERED: Netcat execution${NC}"
    echo "   Expected: HIGH/CRITICAL alert - Network tool execution"
else
    echo -e "${YELLOW}⚠️  Netcat not available, skipping${NC}"
fi

# Python execution
echo "Executing Python interpreter..."
python3 -c "import socket; print('Python network test')" 2>/dev/null || true
echo -e "${GREEN}✅ TRIGGERED: Python interpreter${NC}"
echo "   Expected: WARN/HIGH alert - Script interpreter execution"

# Shell spawning
echo "Spawning bash shell..."
bash -c 'echo "Bash execution test"; whoami' >/dev/null
echo -e "${GREEN}✅ TRIGGERED: Bash shell execution${NC}"
echo "   Expected: WARN alert - Shell execution"
sleep 3

# =============================================================================
# CRITICAL EVENT 4: SENSITIVE FILE ACCESS
# =============================================================================

echo ""
echo -e "${RED}🚨 CRITICAL EVENT 4: Sensitive File Access${NC}"
echo "Accessing sensitive system files..."
sleep 2

# SSH configuration access
sudo cat /etc/ssh/sshd_config | head -3 >/dev/null 2>&1 || true
echo -e "${GREEN}✅ TRIGGERED: SSH configuration access${NC}"
echo "   Expected: HIGH alert - Sensitive configuration file access"

# Shadow file access
sudo ls -la /etc/shadow >/dev/null 2>&1 || true
echo -e "${GREEN}✅ TRIGGERED: Shadow file access${NC}"
echo "   Expected: HIGH alert - Password file access"

# Sudoers file access
sudo ls -la /etc/sudoers >/dev/null 2>&1 || true
echo -e "${GREEN}✅ TRIGGERED: Sudoers file access${NC}"
echo "   Expected: HIGH alert - Privilege escalation file access"
sleep 3

# =============================================================================
# DEMO COMPLETE
# =============================================================================

echo ""
echo -e "${GREEN}🎉 CRITICAL DEMO COMPLETE!${NC}"
echo -e "${GREEN}==========================${NC}"
echo ""
echo -e "${YELLOW}Critical Alerts Generated:${NC}"
echo -e "  🚨 chmod 777 /etc/passwd (CRITICAL)"
echo -e "  🚨 chmod 777 /etc/shadow (CRITICAL)"
echo -e "  ⚠️  External network connections (WARN/HIGH)"
echo -e "  ⚠️  Suspicious command executions (HIGH)"
echo -e "  ⚠️  Sensitive file access (HIGH)"
echo ""
echo -e "${BLUE}📱 CHECK NOW:${NC}"
echo -e "  💬 Slack alerts should be visible"
echo -e "  📊 Kibana/OpenSearch dashboards updated"
echo -e "  📋 Agent logs show event capture"
echo -e "  🎯 Controller logs show classification"
echo ""
echo -e "${GREEN}Perfect for demonstrating:${NC}"
echo -e "  • Real-time threat detection"
echo -e "  • Multi-channel alerting (Slack + logging)"
echo -e "  • Severity-based classification"
echo -e "  • eBPF-based monitoring efficiency"
echo ""

# Cleanup
sudo rm -f /etc/passwd.viva.backup /etc/shadow.viva.backup 2>/dev/null || true

echo -e "${YELLOW}🎯 Your RASP system just demonstrated enterprise-grade security monitoring!${NC}" 