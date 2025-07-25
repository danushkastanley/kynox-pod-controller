#!/bin/bash

# =============================================================================
# Fix Slack Rate Limiting Issues
# =============================================================================
# Adjusts alert configuration to work within Slack's rate limits

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${RED}🚨 Fixing Slack Rate Limiting Issues${NC}"
echo -e "${RED}====================================${NC}"
echo ""

echo -e "${YELLOW}📊 Slack Rate Limits:${NC}"
echo -e "  • 1 message per second per webhook"
echo -e "  • ~30 message burst, then throttled"
echo -e "  • HTTP 429 = Too Many Requests"
echo ""

echo -e "${YELLOW}🔧 Current Problem:${NC}"
echo -e "  • Your RASP system generates alerts faster than Slack accepts"
echo -e "  • Status 429 errors in logs"
echo -e "  • Alerts getting dropped"
echo ""

echo -e "${GREEN}💡 Solutions Available:${NC}"
echo -e "  1. 🐌 Reduce alert rate (5 alerts/minute max)"
echo -e "  2. 🎯 Only critical events (CRITICAL level only)"
echo -e "  3. 📦 Batch/aggregate alerts"
echo -e "  4. 🔇 Disable Slack temporarily for demo"
echo ""

read -p "Choose solution (1-4): " choice

case $choice in
    1)
        echo -e "${GREEN}🐌 Applying Rate Limiting Solution...${NC}"
        
        # Update ConfigMap with very conservative rate limiting
        kubectl patch configmap rasp-controller-config --patch='
        data:
          .env: |
            PORT=50051
            NODE_NAME=${NODE_NAME}
            POD_NAME=${POD_NAME}
            LOG_LEVEL=info
            DEBUG=false
            CLASSIFIER_TYPE=yaml
            RULES_PATH=rules/default-rules.yaml
            CVE_DATA_PATH=data/cve-database.json
            CVE_API_ENDPOINT=https://services.nvd.nist.gov/rest/json/cves/2.0
            CVE_UPDATE_INTERVAL=24h
            SLACK_WEBHOOK_URL=https://hooks.slack.com/services/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
            SLACK_CHANNEL=#alert
            ALERT_WEBHOOK_URL=
            ALERT_EVENT_TYPES=SETUID,PTRACE,BPF_PROG,MOUNT,SECCOMP,CHMOD,OPEN
            ALERT_MIN_LEVEL=warning
            ALERT_RATE_LIMIT=3
        '
        
        echo -e "${GREEN}✅ Rate limited to 3 alerts per minute${NC}"
        ;;
        
    2)
        echo -e "${GREEN}🎯 Applying Critical-Only Solution...${NC}"
        
        kubectl patch configmap rasp-controller-config --patch='
        data:
          .env: |
            PORT=50051
            NODE_NAME=${NODE_NAME}
            POD_NAME=${POD_NAME}
            LOG_LEVEL=info
            DEBUG=false
            CLASSIFIER_TYPE=yaml
            RULES_PATH=rules/default-rules.yaml
            CVE_DATA_PATH=data/cve-database.json
            CVE_API_ENDPOINT=https://services.nvd.nist.gov/rest/json/cves/2.0
            CVE_UPDATE_INTERVAL=24h
            SLACK_WEBHOOK_URL=https://hooks.slack.com/services/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
            SLACK_CHANNEL=#alert
            ALERT_WEBHOOK_URL=
            ALERT_EVENT_TYPES=CHMOD,SETUID,BPF_PROG
            ALERT_MIN_LEVEL=critical
            ALERT_RATE_LIMIT=10
        '
        
        echo -e "${GREEN}✅ Only CRITICAL alerts will be sent${NC}"
        ;;
        
    3)
        echo -e "${GREEN}📦 Applying Alert Aggregation...${NC}"
        echo -e "${YELLOW}ℹ️  This requires code changes - using rate limiting instead${NC}"
        
        kubectl patch configmap rasp-controller-config --patch='
        data:
          .env: |
            PORT=50051
            NODE_NAME=${NODE_NAME}
            POD_NAME=${POD_NAME}
            LOG_LEVEL=info
            DEBUG=false
            CLASSIFIER_TYPE=yaml
            RULES_PATH=rules/default-rules.yaml
            CVE_DATA_PATH=data/cve-database.json
            CVE_API_ENDPOINT=https://services.nvd.nist.gov/rest/json/cves/2.0
            CVE_UPDATE_INTERVAL=24h
            SLACK_WEBHOOK_URL=https://hooks.slack.com/services/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
            SLACK_CHANNEL=#alert
            ALERT_WEBHOOK_URL=
            ALERT_EVENT_TYPES=CHMOD,SETUID,MOUNT,SECCOMP
            ALERT_MIN_LEVEL=high
            ALERT_RATE_LIMIT=2
        '
        
        echo -e "${GREEN}✅ Aggressive rate limiting applied${NC}"
        ;;
        
    4)
        echo -e "${GREEN}🔇 Disabling Slack for Demo...${NC}"
        
        kubectl patch configmap rasp-controller-config --patch='
        data:
          .env: |
            PORT=50051
            NODE_NAME=${NODE_NAME}
            POD_NAME=${POD_NAME}
            LOG_LEVEL=info
            DEBUG=false
            CLASSIFIER_TYPE=yaml
            RULES_PATH=rules/default-rules.yaml
            CVE_DATA_PATH=data/cve-database.json
            CVE_API_ENDPOINT=https://services.nvd.nist.gov/rest/json/cves/2.0
            CVE_UPDATE_INTERVAL=24h
            SLACK_WEBHOOK_URL=
            SLACK_CHANNEL=#alert
            ALERT_WEBHOOK_URL=
            ALERT_EVENT_TYPES=SETUID,PTRACE,BPF_PROG,MOUNT,SECCOMP,CHMOD,OPEN
            ALERT_MIN_LEVEL=warning
            ALERT_RATE_LIMIT=10
        '
        
        echo -e "${GREEN}✅ Slack disabled - alerts will only go to logs${NC}"
        ;;
        
    *)
        echo -e "${RED}❌ Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}🔄 Restarting pod-controller...${NC}"
kubectl rollout restart deployment/pod-controller
kubectl rollout status deployment/pod-controller --timeout=60s

echo ""
echo -e "${GREEN}🎉 Slack Rate Limiting Fixed!${NC}"
echo -e "${GREEN}=============================${NC}"
echo ""

echo -e "${YELLOW}📊 What Changed:${NC}"
case $choice in
    1)
        echo -e "  • Rate limited to 3 alerts per minute"
        echo -e "  • Prevents Slack 429 errors"
        echo -e "  • Perfect for sustained monitoring"
        ;;
    2)
        echo -e "  • Only CRITICAL severity alerts sent"
        echo -e "  • Your chmod 777 demo will still work"
        echo -e "  • Fewer total alerts = no rate limiting"
        ;;
    3)
        echo -e "  • Very aggressive rate limiting (2/minute)"
        echo -e "  • Only most important events"
        echo -e "  • Best for demo scenarios"
        ;;
    4)
        echo -e "  • Slack completely disabled"
        echo -e "  • All alerts go to logs/dashboards only"
        echo -e "  • No rate limiting issues possible"
        ;;
esac

echo ""
echo -e "${BLUE}🧪 Test Your Fix:${NC}"
echo -e "  1. Wait 60 seconds for restart"
echo -e "  2. Run: ${GREEN}./pod-controller/viva-critical-demo.sh${NC}"
echo -e "  3. Check: No more 429 errors in logs"
echo -e "  4. Verify: ${GREEN}kubectl logs -f -l app=pod-controller | grep -i slack${NC}"
echo ""

echo -e "${GREEN}💡 For your viva demo:${NC}"
if [[ $choice == "4" ]]; then
    echo -e "  • Show logs instead of Slack alerts"
    echo -e "  • Highlight dashboard/Kibana integration"
    echo -e "  • Emphasize real-time log analysis"
else
    echo -e "  • Slack alerts will be slower but reliable"
    echo -e "  • Show both Slack and dashboard integration"  
    echo -e "  • Emphasize quality over quantity of alerts"
fi 