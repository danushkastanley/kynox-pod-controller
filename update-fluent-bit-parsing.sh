#!/bin/bash

echo "🔧 Updating Fluent Bit ConfigMap for proper RASP log parsing..."

# Patch the Fluent Bit ConfigMap with better parsers
kubectl patch configmap fluent-bit -n logging --type merge -p '{
  "data": {
    "fluent-bit.conf": "[SERVICE]\n    Flush         5\n    Grace         30\n    Daemon        Off\n    Log_Level     info\n    Parsers_File  parsers.conf\n    HTTP_Server   On\n    HTTP_Listen   0.0.0.0\n    HTTP_Port     2020\n    Health_Check  On\n    storage.path  /tmp/storage\n    storage.sync  normal\n    storage.checksum off\n    storage.backlog.mem_limit 5M\n\n[INPUT]\n    Name              tail\n    Tag               rasp.*\n    Path              /var/log/containers/*rasp*.log,/var/log/containers/*pod-agent*.log\n    Parser            docker\n    DB                /tmp/flb_rasp.db\n    Mem_Buf_Limit     50MB\n    Skip_Long_Lines   On\n    Refresh_Interval  10\n    storage.type      memory\n\n[INPUT]\n    Name              tail\n    Tag               kube.*\n    Path              /var/log/containers/*.log\n    Exclude_Path      /var/log/containers/*_kube-system_*, /var/log/containers/*_logging_*\n    Parser            docker\n    DB                /tmp/flb_kube.db\n    Mem_Buf_Limit     50MB\n    Skip_Long_Lines   On\n    Refresh_Interval  10\n    storage.type      memory\n\n[FILTER]\n    Name                kubernetes\n    Match               *\n    Kube_URL            https://kubernetes.default.svc:443\n    Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt\n    Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token\n    Merge_Log           On\n    K8S-Logging.Parser  On\n    K8S-Logging.Exclude Off\n    Labels              On\n    Annotations         On\n\n# Parse structured RASP logs\n[FILTER]\n    Name                parser\n    Match               rasp.*\n    Key_Name            log\n    Parser              rasp_structured\n    Reserve_Data        On\n    Preserve_Key        On\n\n# Extract JSON from RASP event logs\n[FILTER]\n    Name                parser\n    Match               rasp.*\n    Key_Name            rasp_data\n    Parser              json\n    Reserve_Data        On\n\n# Add metadata for RASP logs\n[FILTER]\n    Name                modify\n    Match               rasp.*\n    Add                 log_type rasp_security\n    Add                 environment development\n\n[OUTPUT]\n    Name                opensearch\n    Match               rasp.*\n    Host                opensearch.logging.svc.cluster.local\n    Port                9200\n    Index               rasp\n    Suppress_Type_Name  On\n    Logstash_Format     On\n    Logstash_Prefix     rasp\n    Logstash_DateFormat %Y.%m.%d\n    Include_Tag_Key     On\n    Tag_Key             @tag\n    Time_Key            @timestamp\n    Retry_Limit         5\n    Replace_Dots        On\n    HTTP_User           \"\"\n    HTTP_Passwd         \"\"\n    tls                 Off\n\n[OUTPUT]\n    Name                opensearch\n    Match               kube.*\n    Host                opensearch.logging.svc.cluster.local\n    Port                9200\n    Index               kubernetes\n    Suppress_Type_Name  On\n    Logstash_Format     On\n    Logstash_Prefix     kubernetes\n    Logstash_DateFormat %Y.%m.%d\n    Include_Tag_Key     On\n    Tag_Key             @tag\n    Time_Key            @timestamp\n    Retry_Limit         5\n    Replace_Dots        On\n    HTTP_User           \"\"\n    HTTP_Passwd         \"\"\n    tls                 Off",
    "parsers.conf": "[PARSER]\n    Name        docker\n    Format      json\n    Time_Key    time\n    Time_Format %Y-%m-%dT%H:%M:%S.%L\n    Time_Keep   On\n\n[PARSER]\n    Name        rasp_structured\n    Format      regex\n    Regex       ^(?<timestamp>[^\\s]+)\\s+(?<stream>\\w+)\\s+(?<logtag>\\w+)\\s+\\[?(?<rasp_data>.*?)\\]?$\n    Time_Key    timestamp\n    Time_Format %Y-%m-%dT%H:%M:%S.%L%z\n\n[PARSER]\n    Name        json\n    Format      json\n    Time_Key    time\n    Time_Format %Y-%m-%dT%H:%M:%S.%L%z\n    Time_Keep   On\n\n[PARSER]\n    Name        cri\n    Format      regex\n    Regex       ^(?<time>[^ ]+) (?<stream>stdout|stderr) (?<logtag>[^ ]*) (?<message>.*)$\n    Time_Key    time\n    Time_Format %Y-%m-%dT%H:%M:%S.%L%z"
  }
}'

if [ $? -eq 0 ]; then
    echo "✅ Fluent Bit ConfigMap updated successfully!"
    
    echo "🔄 Restarting Fluent Bit DaemonSet to apply changes..."
    kubectl rollout restart daemonset/fluent-bit -n logging
    
    echo "⏳ Waiting for Fluent Bit pods to restart..."
    kubectl rollout status daemonset/fluent-bit -n logging --timeout=60s
    
    if [ $? -eq 0 ]; then
        echo "🎉 Fluent Bit updated and restarted successfully!"
        echo "📊 Your RASP logs should now be properly parsed with structured fields!"
        echo ""
        echo "🔍 Check the logs in OpenSearch Dashboards:"
        echo "   - Go to Discover"
        echo "   - Select 'rasp-*' index pattern"
        echo "   - Look for new fields like: event_type, severity, level, etc."
    else
        echo "❌ Failed to restart Fluent Bit DaemonSet"
        exit 1
    fi
else
    echo "❌ Failed to update Fluent Bit ConfigMap"
    exit 1
fi

echo ""
echo "🚀 Your RASP monitoring system now has:"
echo "   ✅ Structured log parsing"
echo "   ✅ Proper field extraction"
echo "   ✅ Enhanced visualizations capability"
echo ""
echo "Now you can create amazing dashboards with:"
echo "   📈 Security events by type"
echo "   🎯 Threat severity breakdown"
echo "   📊 Pod activity metrics"
echo "   ⚡ Real-time security monitoring" 