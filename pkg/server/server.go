package server

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"pod-controller/pkg/alert"
	"pod-controller/pkg/classifier"
	"pod-controller/pkg/filter"
	"pod-controller/pkg/metrics"
	pb "pod-controller/pkg/telemetry"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

type ConnectedAgent struct {
	AgentID   string
	NodeName  string
	PodName   string
	SessionID string
	LastSeen  time.Time
	Metadata  map[string]string
}

type AlertKey struct {
	EventType   string
	Command     string
	Namespace   string
	PodName     string
	ContainerID string
	Severity    string
}

type AlertAggregation struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

type TelemetryServer struct {
	pb.UnimplementedTelemetryServiceServer
	agents          map[string]*ConnectedAgent
	maxAgents       int
	mu              sync.RWMutex
	classifier      classifier.EventClassifierInterface
	threatDetector  *ThreatDetector
	alertLimiter    *rate.Limiter
	alerter         *alert.AlertDispatcher
	namespaceFilter *filter.NamespaceFilter // Namespace filtering
	// Metrics
	eventCounts    map[string]int64
	severityCounts map[string]int64
	promMetrics    *metrics.Metrics // Prometheus metrics
	// Alert aggregation
	alertAggregation map[AlertKey]*AlertAggregation
	maxAggregations  int
	aggregationMu    sync.RWMutex
	metricsMu        sync.RWMutex
	timeout          time.Duration
	startTime        time.Time
	// Filtering stats
	filteredEvents atomic.Int64 // updated concurrently by agent streams
}

// unattributedNamespace labels events the agent could not attribute to a pod.
const unattributedNamespace = "unknown"

func NewTelemetryServer(timeout time.Duration) *TelemetryServer {
	return NewTelemetryServerWithMetrics(timeout, nil)
}

func NewTelemetryServerWithMetrics(timeout time.Duration, promMetrics *metrics.Metrics) *TelemetryServer {
	// Initialize alert dispatcher
	alertDispatcher, err := alert.NewAlertDispatcher()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create alert dispatcher")
	}

	// Create threat detector
	threatDetector := NewThreatDetector()

	// Load classifier configuration from environment
	classifierType := classifier.ClassifierType(getEnvWithDefault("CLASSIFIER_TYPE", "yaml"))
	rulesPath := getEnvWithDefault("RULES_PATH", "rules/default-rules.yaml")
	cveDataPath := getEnvWithDefault("CVE_DATA_PATH", "data/cve-database.json")
	cveAPIKey := os.Getenv("CVE_API_KEY")
	cveAPIEndpoint := getEnvWithDefault("CVE_API_ENDPOINT", "https://services.nvd.nist.gov/rest/json/cves/2.0")

	// Parse CVE update interval
	cveUpdateInterval := 24 * time.Hour // default
	if intervalStr := os.Getenv("CVE_UPDATE_INTERVAL"); intervalStr != "" {
		if parsed, err := time.ParseDuration(intervalStr); err == nil {
			cveUpdateInterval = parsed
		}
	}

	// Create classifier configuration
	classifierConfig := &classifier.ClassifierConfig{
		Type:              classifierType,
		RulesPath:         rulesPath,
		ThreatDetector:    threatDetector,
		FallbackEnabled:   true,
		CVEDataPath:       cveDataPath,
		CVEAPIKey:         cveAPIKey,
		CVEAPIEndpoint:    cveAPIEndpoint,
		CVEUpdateInterval: cveUpdateInterval,
	}

	// Create classifier based on type
	eventClassifier, err := createClassifierByType(classifierConfig, threatDetector)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create classifier")
	}

	logrus.WithFields(logrus.Fields{
		"classifier_type": classifierType,
		"rules_path":      rulesPath,
		"cve_data_path":   cveDataPath,
		"cve_endpoint":    cveAPIEndpoint,
	}).Info("Classifier initialized successfully")

	// Initialize namespace filter
	nsFilter := filter.NewNamespaceFilter()
	if nsFilter.IsIncludeMode() {
		logrus.WithField("namespaces", nsFilter.GetIncludedNamespaces()).Info("Namespace filter: INCLUDE mode")
	} else {
		logrus.WithField("excluded", nsFilter.GetExcludedNamespaces()).Info("Namespace filter: EXCLUDE mode")
	}

	return &TelemetryServer{
		agents:           make(map[string]*ConnectedAgent),
		maxAgents:        defaultMaxConnectedAgents,
		classifier:       eventClassifier,
		threatDetector:   threatDetector,
		alertLimiter:     rate.NewLimiter(rate.Every(1*time.Second), 1),
		alerter:          alertDispatcher,
		namespaceFilter:  nsFilter,
		eventCounts:      make(map[string]int64),
		severityCounts:   make(map[string]int64),
		promMetrics:      promMetrics,
		alertAggregation: make(map[AlertKey]*AlertAggregation),
		maxAggregations:  defaultMaxAlertAggregations,
		timeout:          timeout,
		startTime:        time.Now(),
	}
}

func (s *TelemetryServer) updateMetrics(eventType string, severity classifier.Severity) {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()

	s.eventCounts[eventType]++
	s.severityCounts[string(severity)]++
}

func (s *TelemetryServer) GetMetrics() map[string]interface{} {
	s.metricsMu.RLock()
	defer s.metricsMu.RUnlock()

	return map[string]interface{}{
		"event_counts":    s.eventCounts,
		"severity_counts": s.severityCounts,
	}
}

func (s *TelemetryServer) processEvent(event *pb.SecurityEvent, agent *ConnectedAgent) error {
	// Extract container context
	containerContext := event.GetContainerContext()
	containerId := containerContext["container_id"]
	namespace := containerContext["namespace"]
	podName := containerContext["pod_name"]

	// The agent reports "unknown" when it cannot attribute a process to a pod.
	if namespace == "" {
		namespace = unattributedNamespace
	}
	if podName == "" {
		podName = agent.PodName // fallback to agent pod if target pod unknown
	}

	// Apply namespace filtering to pod events only. Unattributed events (host processes,
	// or containers whose metadata could not be read) have no namespace to filter on, and
	// host activity is where container escapes land, so they are always processed.
	if namespace != unattributedNamespace && !s.namespaceFilter.ShouldMonitor(namespace) {
		filtered := s.filteredEvents.Add(1)
		// Log occasionally to avoid spam
		if filtered%1000 == 1 {
			logrus.WithFields(logrus.Fields{
				"namespace":      namespace,
				"filtered_total": filtered,
			}).Debug("Skipping events from excluded namespace")
		}
		return nil // Silently skip - don't process or alert
	}

	if s.promMetrics != nil {
		processingStart := time.Now()
		defer func() {
			s.promMetrics.RecordEventProcessingDuration(time.Since(processingStart).Seconds())
		}()
	}

	// Initialize fields for logging with clear distinction between agent and target
	fields := logrus.Fields{
		"agent_id":         agent.AgentID,
		"agent_node":       agent.NodeName,
		"agent_pod":        agent.PodName,
		"target_namespace": namespace,
		"target_pod":       podName,
		"target_container": containerId,
		"event_type":       pb.EventType_name[int32(event.EventType)],
		"command":          event.Command,
		"pid":              event.Pid,
		"ppid":             event.Ppid,
		"uid":              event.Uid,
		"gid":              event.Gid,
	}

	// Add optional fields if present
	if event.FilePath != "" {
		fields["file_path"] = event.FilePath
	}
	if event.DestinationIp != "" {
		fields["dst_ip"] = event.DestinationIp
		fields["dst_port"] = event.DestinationPort
	}
	if event.SourceIp != "" {
		fields["src_ip"] = event.SourceIp
		fields["src_port"] = event.SourcePort
	}

	// Classify event severity
	classificationStart := time.Now()
	severity, msg := s.classifier.ClassifyEvent(event)
	if s.promMetrics != nil {
		s.promMetrics.RecordClassificationDuration(time.Since(classificationStart).Seconds())
	}
	fields["severity"] = severity
	fields["message"] = msg

	// Log the event with appropriate level based on severity
	switch severity {
	case classifier.SeverityCritical:
		logrus.WithFields(fields).Error("[CRITICAL] Critical security event detected")
	case classifier.SeverityHigh:
		logrus.WithFields(fields).Error("[HIGH] High severity security event detected")
	case classifier.SeverityWarn:
		logrus.WithFields(fields).Warn("[WARN] Medium severity security event detected")
	case classifier.SeverityLow:
		logrus.WithFields(fields).Info("[LOW] Low severity security event detected")
	default:
		logrus.WithFields(fields).Debug("[DEBUG] Security event detected")
	}

	// Update metrics
	s.updateMetrics(pb.EventType_name[int32(event.EventType)], severity)

	// Record Prometheus metrics
	if s.promMetrics != nil {
		eventTypeName := pb.EventType_name[int32(event.EventType)]
		s.promMetrics.RecordEvent(eventTypeName, string(severity), namespace)
	}

	// Create alert key for aggregation using target pod information
	alertKey := AlertKey{
		EventType:   pb.EventType_name[int32(event.EventType)],
		Command:     event.Command,
		Namespace:   namespace,
		PodName:     podName,
		ContainerID: containerId,
		Severity:    string(severity),
	}

	// Create alert message with clearer context
	var alertMsg string
	if podName == agent.PodName {
		// Event occurred in the monitoring agent itself
		alertMsg = fmt.Sprintf("%s event detected in monitoring agent %s/%s: %s (%s)",
			pb.EventType_name[int32(event.EventType)],
			namespace,
			podName,
			event.Command,
			msg)
	} else {
		// Event occurred in a different pod being monitored
		alertMsg = fmt.Sprintf("%s event detected in pod %s/%s (monitored by %s): %s (%s)",
			pb.EventType_name[int32(event.EventType)],
			namespace,
			podName,
			agent.PodName,
			event.Command,
			msg)
	}

	// Check if we should send alert based on aggregation
	shouldAlert := s.aggregateAlert(alertKey, alertMsg)
	if !shouldAlert && s.promMetrics != nil {
		s.promMetrics.RecordAlertAggregated()
	}
	logrus.WithFields(logrus.Fields{
		"should_alert": shouldAlert,
		"event_type":   alertKey.EventType,
		"severity":     alertKey.Severity,
	}).Debug("[CHECK] Alert aggregation check")

	if shouldAlert {
		// CRITICAL alerts bypass rate limiting for immediate response
		var allowedByRateLimit bool
		if severity == classifier.SeverityCritical {
			allowedByRateLimit = true
			logrus.WithFields(logrus.Fields{
				"rate_limit_allowed": allowedByRateLimit,
				"bypass_reason":      "CRITICAL severity bypasses rate limit",
			}).Info("[CHECK] Rate limit check")
		} else {
			// Apply rate limiting to non-critical events
			allowedByRateLimit = s.alertLimiter.Allow()
			if !allowedByRateLimit && s.promMetrics != nil {
				s.promMetrics.RecordAlertRateLimited()
			}
			logrus.WithFields(logrus.Fields{
				"rate_limit_allowed": allowedByRateLimit,
				"severity":           severity,
			}).Info("[CHECK] Rate limit check")
		}

		if allowedByRateLimit {
			logrus.WithFields(logrus.Fields{
				"alert_level": s.getAlertLevel(severity),
				"title":       fmt.Sprintf("%s Security Event", severity),
			}).Info("[SEND] Preparing to send alert...")

			// Create container context for alert with both agent and target info
			alertContainerContext := map[string]string{
				"monitoring_agent":    agent.PodName,
				"monitoring_node":     agent.NodeName,
				"target_pod":          podName,
				"target_namespace":    namespace,
				"target_container_id": containerId,
			}

			logrus.Info("[START] About to call alerter.Dispatch()...")

			eventTypeName := pb.EventType_name[int32(event.EventType)]
			if err := s.alerter.Dispatch(&alert.Alert{
				Level:     s.getAlertLevel(severity),
				Title:     fmt.Sprintf("%s Security Event", severity),
				Message:   alertMsg,
				AgentID:   agent.AgentID,
				NodeName:  agent.NodeName,
				PodName:   podName,   // Target pod where event occurred
				Namespace: namespace, // Target namespace
				EventType: eventTypeName,
				Command:   event.Command,
				ProcessInfo: map[string]string{
					"pid":  fmt.Sprintf("%d", event.Pid),
					"ppid": fmt.Sprintf("%d", event.Ppid),
					"uid":  fmt.Sprintf("%d", event.Uid),
					"gid":  fmt.Sprintf("%d", event.Gid),
				},
				NetworkInfo: map[string]string{
					"src_ip":   event.SourceIp,
					"src_port": fmt.Sprintf("%d", event.SourcePort),
					"dst_ip":   event.DestinationIp,
					"dst_port": fmt.Sprintf("%d", event.DestinationPort),
				},
				FileInfo: map[string]string{
					"path": event.FilePath,
				},
				SecurityInfo: map[string]string{
					"severity": string(severity),
					"message":  msg,
				},
				ContainerContext: alertContainerContext,
				Timestamp:        time.Now(),
			}); err != nil {
				logrus.WithError(err).Error("Failed to send alert")
				if s.promMetrics != nil {
					s.promMetrics.RecordAlertDispatchError("all", "dispatch_failed")
				}
			} else {
				// Record successful dispatch
				if s.promMetrics != nil {
					s.promMetrics.RecordAlertDispatched("all", string(severity), eventTypeName)
				}
			}
		}
	}

	return nil
}

func (s *TelemetryServer) getAlertLevel(severity classifier.Severity) alert.AlertLevel {
	switch severity {
	case classifier.SeverityCritical:
		return alert.AlertLevelCritical
	case classifier.SeverityHigh:
		return alert.AlertLevelHigh
	case classifier.SeverityWarn:
		return alert.AlertLevelWarning
	case classifier.SeverityLow:
		return alert.AlertLevelInfo
	default:
		return alert.AlertLevelInfo
	}
}

func (s *TelemetryServer) CleanupInactiveAgents() {
	ticker := time.NewTicker(s.timeout / 2)
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, agent := range s.agents {
			if now.Sub(agent.LastSeen) > s.timeout {
				logrus.Printf("[WARN] Removing inactive agent %s (node: %s, pod: %s, last seen: %s ago)",
					id, agent.NodeName, agent.PodName, now.Sub(agent.LastSeen).Round(time.Second))
				// Record Prometheus metric for disconnection
				if s.promMetrics != nil {
					s.promMetrics.RecordAgentDisconnect(agent.NodeName)
				}
				delete(s.agents, id)
			}
		}
		s.mu.Unlock()
	}
}

// getEnvWithDefault returns environment variable value or default if not set
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// createClassifierByType creates the appropriate classifier based on configuration
func createClassifierByType(config *classifier.ClassifierConfig, threatDetector *ThreatDetector) (classifier.EventClassifierInterface, error) {
	switch config.Type {
	case classifier.ClassifierTypeDefault:
		logrus.Info("Using default classifier")
		return classifier.NewEventClassifier(threatDetector), nil

	case classifier.ClassifierTypeYAML:
		logrus.WithField("rules_path", config.RulesPath).Info("Using YAML-based classifier")

		// Create the server-specific classifier config
		serverConfig := &ClassifierConfig{
			RulesPath:       config.RulesPath,
			EnableHotReload: true,
			ValidateRules:   true,
			MetricsEnabled:  true,
		}

		return CreateAdvancedClassifier(serverConfig, threatDetector)

	case classifier.ClassifierTypeCVE:
		logrus.WithFields(logrus.Fields{
			"cve_data_path":   config.CVEDataPath,
			"cve_endpoint":    config.CVEAPIEndpoint,
			"update_interval": config.CVEUpdateInterval,
		}).Info("Using CVE-based classifier")

		// Create CVE classifier (currently uses fallback implementation)
		return classifier.NewCVEClassifier(config)

	default:
		return nil, fmt.Errorf("unknown classifier type: %s", config.Type)
	}
}
