package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the RASP controller
type Metrics struct {
	// Event metrics
	EventsTotal       *prometheus.CounterVec
	EventsBySeverity  *prometheus.CounterVec
	EventsByNamespace prometheus.Counter

	// Agent metrics
	AgentsConnected prometheus.Gauge
	AgentHeartbeats prometheus.Counter

	// Alert metrics
	AlertsDispatched    *prometheus.CounterVec
	AlertsRateLimited   prometheus.Counter
	AlertsAggregated    prometheus.Counter
	AlertDispatchErrors *prometheus.CounterVec

	// Performance metrics
	EventProcessingDuration prometheus.Histogram
	ClassificationDuration  prometheus.Histogram
	GRPCRequestDuration     *prometheus.HistogramVec

	// Classifier metrics
	RuleReloadsTotal *prometheus.CounterVec
	RulesLoaded      prometheus.Gauge
	ClassifierErrors *prometheus.CounterVec

	// System metrics
	UptimeSeconds prometheus.Gauge
	StartTime     prometheus.Gauge
}

// Namespace for all metrics
const metricsNamespace = "rasp"

// NewMetrics creates and registers all Prometheus metrics
func NewMetrics() *Metrics {
	m := &Metrics{
		// Event metrics
		EventsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Name:      "events_total",
				Help:      "Total number of security events processed",
			},
			[]string{"event_type"},
		),
		EventsBySeverity: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Name:      "events_by_severity_total",
				Help:      "Total number of security events by severity level",
			},
			[]string{"severity", "event_type"},
		),
		EventsByNamespace: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Name:      "events_by_namespace_total",
				Help:      "Total number of security events that include namespace context",
			},
		),

		// Agent metrics
		AgentsConnected: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Name:      "agents_connected",
				Help:      "Number of currently connected agents",
			},
		),
		AgentHeartbeats: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Name:      "agent_heartbeats_total",
				Help:      "Total number of heartbeats received from agents",
			},
		),

		// Alert metrics
		AlertsDispatched: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Name:      "alerts_dispatched_total",
				Help:      "Total number of alerts dispatched",
			},
			[]string{"channel", "severity", "event_type"},
		),
		AlertsRateLimited: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Name:      "alerts_rate_limited_total",
				Help:      "Total number of alerts blocked by rate limiting",
			},
		),
		AlertsAggregated: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Name:      "alerts_aggregated_total",
				Help:      "Total number of alerts aggregated (deduplicated)",
			},
		),
		AlertDispatchErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Name:      "alert_dispatch_errors_total",
				Help:      "Total number of alert dispatch errors",
			},
			[]string{"channel", "error_type"},
		),

		// Performance metrics
		EventProcessingDuration: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: metricsNamespace,
				Name:      "event_processing_duration_seconds",
				Help:      "Time spent processing security events",
				Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1},
			},
		),
		ClassificationDuration: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: metricsNamespace,
				Name:      "classification_duration_seconds",
				Help:      "Time spent classifying security events",
				Buckets:   []float64{.00001, .00005, .0001, .0005, .001, .005, .01},
			},
		),
		GRPCRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricsNamespace,
				Name:      "grpc_request_duration_seconds",
				Help:      "Duration of gRPC requests",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method", "status"},
		),

		// Classifier metrics
		RuleReloadsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Name:      "rule_reloads_total",
				Help:      "Total number of rule reload attempts",
			},
			[]string{"status"},
		),
		RulesLoaded: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Name:      "rules_loaded",
				Help:      "Number of security rules currently loaded",
			},
		),
		ClassifierErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Name:      "classifier_errors_total",
				Help:      "Total number of classifier errors",
			},
			[]string{"error_type"},
		),

		// System metrics
		UptimeSeconds: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Name:      "uptime_seconds",
				Help:      "Controller uptime in seconds",
			},
		),
		StartTime: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Name:      "start_time_seconds",
				Help:      "Controller start time as Unix timestamp",
			},
		),
	}

	return m
}

// RecordEvent records a security event with its metadata
func (m *Metrics) RecordEvent(eventType, severity, namespace string) {
	m.EventsTotal.WithLabelValues(eventType).Inc()
	m.EventsBySeverity.WithLabelValues(severity, eventType).Inc()
	if namespace != "" {
		m.EventsByNamespace.Inc()
	}
}

// RecordAgentConnect records an agent connection
func (m *Metrics) RecordAgentConnect(_ string) {
	m.AgentsConnected.Inc()
}

// RecordAgentDisconnect records an agent disconnection
func (m *Metrics) RecordAgentDisconnect(_ string) {
	m.AgentsConnected.Dec()
}

// RecordHeartbeat records an agent heartbeat
func (m *Metrics) RecordHeartbeat(_, _ string) {
	m.AgentHeartbeats.Inc()
}

// RecordAlertDispatched records a dispatched alert
func (m *Metrics) RecordAlertDispatched(channel, severity, eventType string) {
	m.AlertsDispatched.WithLabelValues(channel, severity, eventType).Inc()
}

// RecordAlertRateLimited records a rate-limited alert
func (m *Metrics) RecordAlertRateLimited() {
	m.AlertsRateLimited.Inc()
}

// RecordAlertAggregated records an aggregated alert
func (m *Metrics) RecordAlertAggregated() {
	m.AlertsAggregated.Inc()
}

// RecordAlertDispatchError records an alert dispatch error
func (m *Metrics) RecordAlertDispatchError(channel, errorType string) {
	m.AlertDispatchErrors.WithLabelValues(channel, errorType).Inc()
}

// RecordEventProcessingDuration records event processing time
func (m *Metrics) RecordEventProcessingDuration(seconds float64) {
	m.EventProcessingDuration.Observe(seconds)
}

// RecordClassificationDuration records classification time
func (m *Metrics) RecordClassificationDuration(seconds float64) {
	m.ClassificationDuration.Observe(seconds)
}

// RecordGRPCRequest records a gRPC request duration
func (m *Metrics) RecordGRPCRequest(method, status string, seconds float64) {
	m.GRPCRequestDuration.WithLabelValues(method, status).Observe(seconds)
}

// RecordRuleReload records a rule reload attempt
func (m *Metrics) RecordRuleReload(success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	m.RuleReloadsTotal.WithLabelValues(status).Inc()
}

// SetRulesLoaded sets the number of loaded rules
func (m *Metrics) SetRulesLoaded(count int) {
	m.RulesLoaded.Set(float64(count))
}

// RecordClassifierError records a classifier error
func (m *Metrics) RecordClassifierError(errorType string) {
	m.ClassifierErrors.WithLabelValues(errorType).Inc()
}

// SetUptime sets the current uptime
func (m *Metrics) SetUptime(seconds float64) {
	m.UptimeSeconds.Set(seconds)
}

// SetStartTime sets the start time
func (m *Metrics) SetStartTime(unixTime float64) {
	m.StartTime.Set(unixTime)
}
