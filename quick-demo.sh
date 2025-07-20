#!/bin/bash

echo "🚨 RASP Security Demo - Quick Test"
echo "=================================="

# Function to check if events are being generated
check_events() {
    echo "🔍 Checking recent security events..."
    kubectl logs deployment/rasp-controller --tail=10 | grep -E "(security event detected|chmod|exec)" | tail -3
}

echo ""
echo "🎯 Generating Security Events..."

echo "Step 1: File permission changes (chmod)"
kubectl exec demo-target -- bash -c "touch /tmp/demo1 && chmod 777 /tmp/demo1"
sleep 1
check_events

echo ""
echo "Step 2: Process execution"  
kubectl exec demo-target -- bash -c "whoami && ps aux | head -3"
sleep 1
check_events

echo ""
echo "Step 3: File operations"
kubectl exec demo-target -- bash -c "echo 'test' > /tmp/demo2 && cat /tmp/demo2"
sleep 1
check_events

echo ""
echo "📊 Recent Events Summary:"
kubectl logs deployment/rasp-controller --tail=20 | grep -E "(event detected|chmod|exec|demo)"

echo ""
echo "✅ Demo test complete!" 