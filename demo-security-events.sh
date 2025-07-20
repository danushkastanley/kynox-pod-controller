#!/bin/bash

# =============================================================================
# RASP Security Demo Script
# =============================================================================
# This script demonstrates how to trigger security alerts on-demand for demos
# Each command will trigger a specific alert type that you can show to audience

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}🚨 RASP Security Event Demo Script${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""
echo -e "${YELLOW}This script will help you trigger security alerts during demos.${NC}"
echo -e "${YELLOW}Make sure you're running this inside a pod being monitored.${NC}"
echo ""

# Function to wait for user input
wait_for_demo() {
    echo -e "${CYAN}Press ENTER when ready to demonstrate this attack...${NC}"
    read -r
}

# Function to show alert expectation
show_alert_info() {
    local event_type=$1
    local description=$2
    echo -e "${GREEN}📡 Expected Alert: ${YELLOW}$event_type${GREEN} - $description${NC}"
    echo ""
}

echo -e "${BLUE}Available Demo Attacks:${NC}"
echo -e "1. ${YELLOW}CHMOD${NC} - File permission manipulation"
echo -e "2. ${YELLOW}SETUID${NC} - Privilege escalation attempt"
echo -e "3. ${YELLOW}PTRACE${NC} - Process injection/debugging"
echo -e "4. ${YELLOW}MOUNT${NC} - Container escape attempt"
echo -e "5. ${YELLOW}EXEC${NC} - Suspicious command execution"
echo ""

echo -e "${RED}Select demo scenario:${NC}"
echo "1) Run all demos in sequence"
echo "2) File Permission Attack (CHMOD)"
echo "3) Privilege Escalation Attack (SETUID)"  
echo "4) Process Injection Attack (PTRACE)"
echo "5) Container Escape Attack (MOUNT)"
echo "6) Suspicious Command Execution (EXEC)"
echo "7) Exit"
echo ""

read -p "Enter your choice (1-7): " choice

case $choice in
    1)
        echo -e "${BLUE}🎭 Running Complete Security Demo Sequence${NC}"
        echo -e "${BLUE}=========================================${NC}"
        ;;
    2)
        choice="chmod_demo"
        ;;
    3)
        choice="setuid_demo"
        ;;
    4)
        choice="ptrace_demo"
        ;;
    5)
        choice="mount_demo"
        ;;
    6)
        choice="exec_demo"
        ;;
    7)
        echo -e "${GREEN}Demo completed!${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

# Demo 1: CHMOD Attack - File Permission Manipulation
if [[ "$choice" == "1" || "$choice" == "chmod_demo" ]]; then
    echo -e "${BLUE}🔐 Demo 1: File Permission Manipulation Attack${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${YELLOW}Scenario: Attacker tries to make /etc/passwd world-writable${NC}"
    show_alert_info "CHMOD" "Critical file permission change detected"
    wait_for_demo
    
    echo -e "${RED}🔨 Executing: chmod 777 /etc/passwd${NC}"
    chmod 777 /etc/passwd 2>/dev/null || echo -e "${YELLOW}⚠️ Command may fail but alert should still fire${NC}"
    
    echo -e "${GREEN}✅ CHMOD alert should appear in Slack now!${NC}"
    echo ""
    sleep 3
fi

# Demo 2: SETUID Attack - Privilege Escalation 
if [[ "$choice" == "1" || "$choice" == "setuid_demo" ]]; then
    echo -e "${BLUE}⬆️ Demo 2: Privilege Escalation Attack${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo -e "${YELLOW}Scenario: Attacker attempts to escalate privileges${NC}"
    show_alert_info "SETUID" "Privilege escalation attempt detected"
    wait_for_demo
    
    echo -e "${RED}🔨 Executing: chmod +s /bin/bash${NC}"
    chmod +s /bin/bash 2>/dev/null || echo -e "${YELLOW}⚠️ Command may fail but may trigger SETUID monitoring${NC}"
    
    # Alternative SETUID trigger
    echo -e "${RED}🔨 Alternative: Creating setuid binary${NC}"
    cat > /tmp/setuid_test.c << 'EOF'
#include <unistd.h>
#include <stdio.h>
int main() {
    setuid(0);
    printf("SETUID test\n");
    return 0;
}
EOF
    
    if command -v gcc >/dev/null 2>&1; then
        gcc /tmp/setuid_test.c -o /tmp/setuid_test 2>/dev/null || true
        chmod +s /tmp/setuid_test 2>/dev/null || true
        /tmp/setuid_test 2>/dev/null || true
    else
        echo -e "${YELLOW}⚠️ GCC not available, using alternative method${NC}"
        # This should trigger SETUID monitoring
        echo "0" > /proc/self/uid_map 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✅ SETUID alert should appear in Slack now!${NC}"
    echo ""
    sleep 3
fi

# Demo 3: PTRACE Attack - Process Injection
if [[ "$choice" == "1" || "$choice" == "ptrace_demo" ]]; then
    echo -e "${BLUE}🎯 Demo 3: Process Injection Attack${NC}"
    echo -e "${BLUE}==============================${NC}"
    echo -e "${YELLOW}Scenario: Attacker attempts to debug/inject into processes${NC}"
    show_alert_info "PTRACE" "Process debugging/injection attempt detected"
    wait_for_demo
    
    # Create a simple target process
    echo -e "${RED}🔨 Executing: ptrace-based process debugging${NC}"
    
    # Start a background process to attach to
    sleep 300 &
    TARGET_PID=$!
    
    # Try to attach with gdb (if available)
    if command -v gdb >/dev/null 2>&1; then
        echo -e "${RED}🔨 Using GDB to attach to process $TARGET_PID${NC}"
        timeout 2 gdb -batch -ex "attach $TARGET_PID" -ex "detach" -ex "quit" 2>/dev/null || true
    elif command -v strace >/dev/null 2>&1; then
        echo -e "${RED}🔨 Using strace to trace process $TARGET_PID${NC}"
        timeout 2 strace -p $TARGET_PID 2>/dev/null || true
    else
        echo -e "${YELLOW}⚠️ No debugging tools available, creating manual ptrace call${NC}"
        # Manual ptrace system call if possible
        cat > /tmp/ptrace_test.c << 'EOF'
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
int main() {
    long result = ptrace(PTRACE_ATTACH, 1, NULL, NULL);
    printf("PTRACE result: %ld\n", result);
    return 0;
}
EOF
        if command -v gcc >/dev/null 2>&1; then
            gcc /tmp/ptrace_test.c -o /tmp/ptrace_test 2>/dev/null || true
            /tmp/ptrace_test 2>/dev/null || true
        fi
    fi
    
    # Clean up
    kill $TARGET_PID 2>/dev/null || true
    
    echo -e "${GREEN}✅ PTRACE alert should appear in Slack now!${NC}"
    echo ""
    sleep 3
fi

# Demo 4: MOUNT Attack - Container Escape
if [[ "$choice" == "1" || "$choice" == "mount_demo" ]]; then
    echo -e "${BLUE}🚪 Demo 4: Container Escape Attempt${NC}"
    echo -e "${BLUE}===============================${NC}"
    echo -e "${YELLOW}Scenario: Attacker attempts to mount host filesystem${NC}"
    show_alert_info "MOUNT" "Container escape attempt detected"
    wait_for_demo
    
    echo -e "${RED}🔨 Executing: Suspicious mount operations${NC}"
    
    # Try various mount operations that would be suspicious
    echo -e "${RED}🔨 Attempting to mount /proc${NC}"
    mount -t proc proc /tmp/proc_mount 2>/dev/null || echo -e "${YELLOW}⚠️ Mount failed (expected) but should trigger alert${NC}"
    
    echo -e "${RED}🔨 Attempting to mount host filesystem${NC}"
    mount /dev/sda1 /mnt 2>/dev/null || echo -e "${YELLOW}⚠️ Mount failed (expected) but should trigger alert${NC}"
    
    echo -e "${RED}🔨 Attempting bind mount${NC}"
    mount --bind /proc /tmp/bind_proc 2>/dev/null || echo -e "${YELLOW}⚠️ Mount failed (expected) but should trigger alert${NC}"
    
    echo -e "${GREEN}✅ MOUNT alert should appear in Slack now!${NC}"
    echo ""
    sleep 3
fi

# Demo 5: EXEC Attack - Suspicious Command Execution
if [[ "$choice" == "1" || "$choice" == "exec_demo" ]]; then
    echo -e "${BLUE}💻 Demo 5: Suspicious Command Execution${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo -e "${YELLOW}Scenario: Attacker runs known malicious tools${NC}"
    show_alert_info "EXEC" "Suspicious command execution detected"
    wait_for_demo
    
    echo -e "${RED}🔨 Executing: Known attack tools and techniques${NC}"
    
    # Execute various suspicious commands
    echo -e "${RED}🔨 Running: nc (netcat) for reverse shell${NC}"
    nc -h >/dev/null 2>&1 || echo -e "${YELLOW}⚠️ nc not available${NC}"
    
    echo -e "${RED}🔨 Running: wget to download payload${NC}"
    wget --help >/dev/null 2>&1 || echo -e "${YELLOW}⚠️ wget not available${NC}"
    
    echo -e "${RED}🔨 Running: base64 for payload encoding${NC}"
    echo "malicious_payload" | base64 >/dev/null 2>&1 || true
    
    echo -e "${RED}🔨 Running: curl to external C&C server${NC}"
    curl --version >/dev/null 2>&1 || echo -e "${YELLOW}⚠️ curl not available${NC}"
    
    echo -e "${RED}🔨 Running: suspicious shell operations${NC}"
    /bin/bash -c "echo 'This could be a reverse shell'" >/dev/null 2>&1 || true
    
    echo -e "${GREEN}✅ EXEC alerts should appear in Slack now!${NC}"
    echo ""
    sleep 3
fi

echo -e "${GREEN}🎉 Demo completed!${NC}"
echo -e "${CYAN}Check your Slack #alert channel for the security alerts.${NC}"
echo ""
echo -e "${BLUE}💡 Pro Tips for Demo:${NC}"
echo -e "  • Run each attack in sequence to show different threat types"
echo -e "  • Explain the security context of each attack to audience"  
echo -e "  • Show the Slack alerts appearing in real-time"
echo -e "  • Demonstrate how RASP provides immediate threat detection"
echo ""

echo "🚨 RASP Security Demo - Generating Security Events"
echo "================================================"

# Function to check if events are being generated
check_events() {
    echo "🔍 Checking recent security events..."
    kubectl logs deployment/rasp-controller --tail=20 | grep -E "(CRITICAL|HIGH|security event detected)" | tail -5
}

echo ""
echo "📋 Demo Events to Generate:"
echo "1. File permission changes (chmod)"
echo "2. Process execution events" 
echo "3. Network connections"
echo "4. Privilege escalation attempts"
echo ""

echo "🎯 Step 1: File Permission Changes"
kubectl exec -it demo-target -- bash -c "
echo 'Creating files and changing permissions...'
touch /tmp/demo-file-1
chmod 777 /tmp/demo-file-1
touch /tmp/demo-file-2  
chmod 755 /tmp/demo-file-2
touch /tmp/demo-file-3
chmod 644 /tmp/demo-file-3
echo 'File operations completed'
"

sleep 2
check_events

echo ""
echo "🎯 Step 2: Process Execution Events"
kubectl exec -it demo-target -- bash -c "
echo 'Executing various commands...'
whoami
ps aux | head -5
ls -la /tmp/
cat /etc/passwd | head -5
echo 'Command executions completed'
"

sleep 2  
check_events

echo ""
echo "🎯 Step 3: Network Activity" 
kubectl exec -it demo-target -- bash -c "
echo 'Testing network connections...'
curl -s http://httpbin.org/ip --connect-timeout 5 || echo 'Network request attempted'
wget -q --timeout=5 --tries=1 http://example.com -O /dev/null || echo 'Download attempted'
echo 'Network tests completed'
"

sleep 2
check_events

echo ""
echo "🎯 Step 4: File System Operations"
kubectl exec -it demo-target -- bash -c "
echo 'Creating and modifying files...'
echo 'test content' > /tmp/demo-output.txt
cat /tmp/demo-output.txt
rm /tmp/demo-output.txt
echo 'File system operations completed'
"

sleep 2
check_events

echo ""
echo "📊 Final Security Event Summary:"
echo "================================="
kubectl logs deployment/rasp-controller --tail=50 | grep -E "(security event detected|CRITICAL|HIGH|chmod|exec)" | tail -10

echo ""
echo "✅ Demo Complete! Check the controller logs for security events."
echo "📋 To see all recent events:"
echo "   kubectl logs deployment/rasp-controller --tail=100" 