package server

import (
	"sync"
	"sync/atomic"
	"time"

	"pod-controller/pkg/classifier"
	pb "pod-controller/pkg/telemetry"
)

// ClassifierMetrics tracks comprehensive metrics for the classifier
type ClassifierMetrics struct {
	mu sync.RWMutex

	// Event classification metrics
	totalEvents      int64
	eventsBySeverity map[classifier.Severity]int64
	eventsByType     map[pb.EventType]int64
	validationErrors int64
	skippedEvents    int64

	// Performance metrics
	avgClassificationTime   time.Duration
	totalClassificationTime time.Duration
	classificationCount     int64

	// Rule management metrics
	ruleReloads       int64
	successfulReloads int64
	failedReloads     int64
	lastReloadTime    time.Time

	// Time tracking
	startTime time.Time
}

// newClassifierMetrics creates a new metrics instance
func newClassifierMetrics() *ClassifierMetrics {
	return &ClassifierMetrics{
		eventsBySeverity: make(map[classifier.Severity]int64),
		eventsByType:     make(map[pb.EventType]int64),
		startTime:        time.Now(),
	}
}

// recordClassification records a successful classification
func (m *ClassifierMetrics) recordClassification(eventType pb.EventType, severity classifier.Severity, duration time.Duration) {
	atomic.AddInt64(&m.totalEvents, 1)
	atomic.AddInt64(&m.classificationCount, 1)
	atomic.AddInt64((*int64)(&m.totalClassificationTime), int64(duration))

	m.mu.Lock()
	defer m.mu.Unlock()

	m.eventsBySeverity[severity]++
	m.eventsByType[eventType]++

	// Update average classification time
	if m.classificationCount > 0 {
		m.avgClassificationTime = time.Duration(int64(m.totalClassificationTime) / m.classificationCount)
	}
}

// recordValidationError records a validation error
func (m *ClassifierMetrics) recordValidationError() {
	atomic.AddInt64(&m.validationErrors, 1)
}

// recordSkippedEvent records a skipped event
func (m *ClassifierMetrics) recordSkippedEvent(eventType pb.EventType) {
	atomic.AddInt64(&m.skippedEvents, 1)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventsByType[eventType]++ // Still count it for type tracking
}

// recordSuccessfulReload records a successful rule reload
func (m *ClassifierMetrics) recordSuccessfulReload() {
	atomic.AddInt64(&m.ruleReloads, 1)
	atomic.AddInt64(&m.successfulReloads, 1)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastReloadTime = time.Now()
}

// recordReloadError records a failed rule reload
func (m *ClassifierMetrics) recordReloadError() {
	atomic.AddInt64(&m.ruleReloads, 1)
	atomic.AddInt64(&m.failedReloads, 1)
}

// getMetrics returns a comprehensive metrics snapshot
func (m *ClassifierMetrics) getMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Calculate uptime
	uptime := time.Since(m.startTime)

	// Events per severity
	severityMetrics := make(map[string]int64)
	for severity, count := range m.eventsBySeverity {
		severityMetrics[string(severity)] = count
	}

	// Events per type
	typeMetrics := make(map[string]int64)
	for eventType, count := range m.eventsByType {
		typeMetrics[pb.EventType_name[int32(eventType)]] = count
	}

	// Performance metrics
	eventsPerSecond := float64(0)
	if uptime.Seconds() > 0 {
		eventsPerSecond = float64(atomic.LoadInt64(&m.totalEvents)) / uptime.Seconds()
	}

	return map[string]interface{}{
		"uptime": map[string]interface{}{
			"seconds": uptime.Seconds(),
			"started": m.startTime.Format(time.RFC3339),
		},
		"events": map[string]interface{}{
			"total":             atomic.LoadInt64(&m.totalEvents),
			"validation_errors": atomic.LoadInt64(&m.validationErrors),
			"skipped":           atomic.LoadInt64(&m.skippedEvents),
			"events_per_second": eventsPerSecond,
			"by_severity":       severityMetrics,
			"by_type":           typeMetrics,
		},
		"performance": map[string]interface{}{
			"avg_classification_time_ms":   m.avgClassificationTime.Milliseconds(),
			"total_classification_time_ms": m.totalClassificationTime.Milliseconds(),
			"classification_count":         atomic.LoadInt64(&m.classificationCount),
		},
		"rules": map[string]interface{}{
			"total_reloads":      atomic.LoadInt64(&m.ruleReloads),
			"successful_reloads": atomic.LoadInt64(&m.successfulReloads),
			"failed_reloads":     atomic.LoadInt64(&m.failedReloads),
			"last_reload":        m.lastReloadTime.Format(time.RFC3339),
		},
	}
}

// GetSummary returns a concise metrics summary
func (m *ClassifierMetrics) GetSummary() map[string]interface{} {
	uptime := time.Since(m.startTime)
	totalEvents := atomic.LoadInt64(&m.totalEvents)
	validationErrors := atomic.LoadInt64(&m.validationErrors)

	errorRate := float64(0)
	if totalEvents > 0 {
		errorRate = float64(validationErrors) / float64(totalEvents) * 100
	}

	eventsPerSecond := float64(0)
	if uptime.Seconds() > 0 {
		eventsPerSecond = float64(totalEvents) / uptime.Seconds()
	}

	return map[string]interface{}{
		"total_events":               totalEvents,
		"validation_errors":          validationErrors,
		"error_rate_percent":         errorRate,
		"events_per_second":          eventsPerSecond,
		"uptime_hours":               uptime.Hours(),
		"avg_classification_time_ms": m.avgClassificationTime.Milliseconds(),
	}
}

// Reset resets all metrics (useful for testing)
func (m *ClassifierMetrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	atomic.StoreInt64(&m.totalEvents, 0)
	atomic.StoreInt64(&m.validationErrors, 0)
	atomic.StoreInt64(&m.skippedEvents, 0)
	atomic.StoreInt64(&m.classificationCount, 0)
	atomic.StoreInt64(&m.ruleReloads, 0)
	atomic.StoreInt64(&m.successfulReloads, 0)
	atomic.StoreInt64(&m.failedReloads, 0)

	m.eventsBySeverity = make(map[classifier.Severity]int64)
	m.eventsByType = make(map[pb.EventType]int64)
	m.avgClassificationTime = 0
	m.totalClassificationTime = 0
	m.startTime = time.Now()
	m.lastReloadTime = time.Time{}
}
