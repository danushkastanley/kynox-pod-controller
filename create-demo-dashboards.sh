#!/bin/bash

echo "🎨 Creating RASP Security Monitoring Dashboards..."
echo "================================================="

# OpenSearch endpoint
OPENSEARCH_URL="http://localhost:30001"

# Function to create index patterns
create_index_patterns() {
    echo "📋 Creating Index Patterns..."
    
    # Create RASP index pattern
    curl -X POST "$OPENSEARCH_URL/_dashboards/api/saved_objects/index-pattern" \
        -H "Content-Type: application/json" \
        -H "osd-xsrf: true" \
        -d '{
            "attributes": {
                "title": "rasp-*",
                "timeFieldName": "@timestamp",
                "fields": "[{\"name\":\"@timestamp\",\"type\":\"date\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"event_type\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"severity\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"kubernetes.pod_name\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true},{\"name\":\"kubernetes.namespace_name\",\"type\":\"string\",\"searchable\":true,\"aggregatable\":true}]"
            }
        }' 2>/dev/null || echo "Index pattern may already exist"

    # Create Kubernetes index pattern  
    curl -X POST "$OPENSEARCH_URL/_dashboards/api/saved_objects/index-pattern" \
        -H "Content-Type: application/json" \
        -H "osd-xsrf: true" \
        -d '{
            "attributes": {
                "title": "kubernetes-*",
                "timeFieldName": "@timestamp"
            }
        }' 2>/dev/null || echo "Index pattern may already exist"
}

# Function to create visualizations
create_visualizations() {
    echo "📊 Creating Security Visualizations..."
    
    # Security Events Timeline
    curl -X POST "$OPENSEARCH_URL/_dashboards/api/saved_objects/visualization" \
        -H "Content-Type: application/json" \
        -H "osd-xsrf: true" \
        -d '{
            "attributes": {
                "title": "RASP Security Events Timeline",
                "visState": "{\"title\":\"RASP Security Events Timeline\",\"type\":\"line\",\"params\":{\"grid\":{\"categoryLines\":false,\"style\":{\"color\":\"#eee\"}},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"line\",\"mode\":\"normal\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"schema\":\"segment\",\"params\":{\"field\":\"@timestamp\",\"interval\":\"auto\",\"customInterval\":\"2h\",\"min_doc_count\":1,\"extended_bounds\":{}}}]}",
                "uiStateJSON": "{}",
                "description": "",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"rasp-*\",\"query\":{\"match_all\":{}},\"filter\":[]}"
                }
            }
        }' 2>/dev/null

    # Security Events by Severity
    curl -X POST "$OPENSEARCH_URL/_dashboards/api/saved_objects/visualization" \
        -H "Content-Type: application/json" \
        -H "osd-xsrf: true" \
        -d '{
            "attributes": {
                "title": "Security Events by Severity",
                "visState": "{\"title\":\"Security Events by Severity\",\"type\":\"pie\",\"params\":{\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"event_severity\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\"}}]}",
                "uiStateJSON": "{}",
                "description": "",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"rasp-*\",\"query\":{\"match_all\":{}},\"filter\":[]}"
                }
            }
        }' 2>/dev/null

    # Pod Activity Heatmap
    curl -X POST "$OPENSEARCH_URL/_dashboards/api/saved_objects/visualization" \
        -H "Content-Type: application/json" \
        -H "osd-xsrf: true" \
        -d '{
            "attributes": {
                "title": "Pod Security Activity Heatmap",
                "visState": "{\"title\":\"Pod Security Activity Heatmap\",\"type\":\"histogram\",\"params\":{\"grid\":{\"categoryLines\":false,\"style\":{\"color\":\"#eee\"}},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"kubernetes.pod_name\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\"}}]}",
                "uiStateJSON": "{}",
                "description": "",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"rasp-*\",\"query\":{\"match_all\":{}},\"filter\":[]}"
                }
            }
        }' 2>/dev/null
}

# Function to create the main dashboard
create_main_dashboard() {
    echo "🚀 Creating Main RASP Security Dashboard..."
    
    curl -X POST "$OPENSEARCH_URL/_dashboards/api/saved_objects/dashboard" \
        -H "Content-Type: application/json" \
        -H "osd-xsrf: true" \
        -d '{
            "attributes": {
                "title": "🛡️ RASP Security Monitoring Dashboard",
                "hits": 0,
                "description": "Real-time Application Security Monitoring for Microservices",
                "panelsJSON": "[{\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":15,\"i\":\"1\"},\"panelIndex\":\"1\",\"embeddableConfig\":{},\"panelRefName\":\"panel_1\"},{\"gridData\":{\"x\":24,\"y\":0,\"w\":24,\"h\":15,\"i\":\"2\"},\"panelIndex\":\"2\",\"embeddableConfig\":{},\"panelRefName\":\"panel_2\"},{\"gridData\":{\"x\":0,\"y\":15,\"w\":48,\"h\":15,\"i\":\"3\"},\"panelIndex\":\"3\",\"embeddableConfig\":{},\"panelRefName\":\"panel_3\"}]",
                "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
                "version": 1,
                "timeRestore": false,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"query\":{\"match_all\":{}},\"filter\":[]}"
                }
            }
        }' 2>/dev/null
}

# Function to check OpenSearch connectivity
check_opensearch() {
    echo "🔍 Checking OpenSearch connectivity..."
    if curl -s "$OPENSEARCH_URL" >/dev/null 2>&1; then
        echo "✅ OpenSearch is accessible at $OPENSEARCH_URL"
        return 0
    else
        echo "❌ Cannot connect to OpenSearch at $OPENSEARCH_URL"
        echo "💡 Make sure:"
        echo "   1. OpenSearch is running: kubectl get pods -n logging"
        echo "   2. Port forwarding is active: kubectl port-forward -n logging svc/opensearch-cluster-master 30001:9200"
        echo "   3. Try accessing http://localhost:30001 in your browser"
        return 1
    fi
}

# Function to generate sample search queries
create_sample_queries() {
    echo "📝 Creating Sample Search Queries..."
    
    cat > rasp-sample-queries.txt << 'EOF'
# RASP Security Monitoring - Sample Queries for OpenSearch Dashboards

## 1. High Severity Security Events
event_severity:"HIGH" AND @timestamp:[now-1h TO now]

## 2. File Access Monitoring
event_type:"OPEN" AND log:"/etc/passwd"

## 3. Network Connection Analysis
event_type:"CONNECT" AND event_pid:>1000

## 4. Pod-specific Security Events
kubernetes.pod_name:"pod-agent-*" AND event_severity:("HIGH" OR "MEDIUM")

## 5. Time-based Security Analysis
@timestamp:[now-24h TO now] AND event_type:("OPEN" OR "CONNECT" OR "EXEC")

## 6. Container Process Monitoring
kubernetes.container_name:"pod-agent" AND event_type:"EXEC"

## 7. Security Event Correlation
(event_type:"OPEN" AND log:"/bin/bash") OR (event_type:"EXEC" AND event_command:"/bin/sh")

## 8. Namespace Security Monitoring
kubernetes.namespace_name:"default" AND event_severity:"HIGH"

## 9. Resource Access Patterns
event_type:"OPEN" AND (log:"*.conf" OR log:"*.cfg" OR log:"*.yaml")

## 10. Anomaly Detection Query
NOT event_type:("OPEN" OR "CLOSE") AND event_severity:("HIGH" OR "CRITICAL")
EOF

    echo "✅ Sample queries saved to rasp-sample-queries.txt"
}

# Main execution
main() {
    echo "🎯 Starting Dashboard Creation Process..."
    echo ""
    
    # Check connectivity first
    if ! check_opensearch; then
        exit 1
    fi
    
    echo ""
    echo "🏗️ Building Dashboard Components..."
    
    # Create index patterns
    create_index_patterns
    sleep 2
    
    # Create visualizations
    create_visualizations
    sleep 2
    
    # Create main dashboard
    create_main_dashboard
    sleep 2
    
    # Create sample queries
    create_sample_queries
    
    echo ""
    echo "🎉 Dashboard Creation Complete!"
    echo "=============================="
    echo ""
    echo "🌐 Access your dashboards at: http://localhost:30001"
    echo ""
    echo "📊 Available Dashboards:"
    echo "  • 🛡️ RASP Security Monitoring Dashboard (Main)"
    echo "  • 📈 RASP Security Events Timeline"
    echo "  • 🥧 Security Events by Severity"
    echo "  • 🔥 Pod Security Activity Heatmap"
    echo ""
    echo "🔍 To explore your data:"
    echo "  1. Go to Discover → Select 'rasp-*' index"
    echo "  2. Use the sample queries in 'rasp-sample-queries.txt'"
    echo "  3. Create custom visualizations based on your needs"
    echo ""
    echo "💡 Pro Tips for your demo:"
    echo "  • Set time range to 'Last 1 hour' or 'Last 24 hours'"
    echo "  • Filter by event_severity:'HIGH' for security incidents"
    echo "  • Show real-time updates by setting auto-refresh"
    echo "  • Use the search bar for live filtering"
    echo ""
    echo "🎊 Your RASP monitoring is ready to impress! 🎊"
}

# Run the main function
main 