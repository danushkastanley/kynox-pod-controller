package server

import (
	"strings"
	"time"
)

const (
	defaultMaxAlertAggregations = 2_048
	maxAggregationValueBytes    = 256
	alertAggregationTTL         = 5 * time.Minute
)

func (s *TelemetryServer) aggregateAlert(key AlertKey, _ string) bool {
	now := time.Now()
	key = boundedAlertKey(key)

	s.aggregationMu.Lock()
	defer s.aggregationMu.Unlock()

	if aggregation, exists := s.alertAggregation[key]; exists {
		if now.Sub(aggregation.LastSeen) > alertAggregationTTL {
			s.alertAggregation[key] = newAlertAggregation(now)
			return true
		}

		aggregation.Count++
		aggregation.LastSeen = now
		if aggregation.Count%10 == 0 || now.Sub(aggregation.FirstSeen) >= time.Minute {
			aggregation.FirstSeen = now
			return true
		}
		return false
	}

	s.pruneAlertAggregations(now)
	for len(s.alertAggregation) >= s.aggregationLimit() {
		s.evictOldestAlertAggregation()
	}
	s.alertAggregation[key] = newAlertAggregation(now)
	return true
}

func (s *TelemetryServer) pruneAlertAggregations(now time.Time) {
	for key, aggregation := range s.alertAggregation {
		if now.Sub(aggregation.LastSeen) > alertAggregationTTL {
			delete(s.alertAggregation, key)
		}
	}
}

func (s *TelemetryServer) evictOldestAlertAggregation() {
	var oldestKey AlertKey
	var oldest *AlertAggregation
	for key, aggregation := range s.alertAggregation {
		if oldest == nil || aggregation.LastSeen.Before(oldest.LastSeen) ||
			(aggregation.LastSeen.Equal(oldest.LastSeen) && alertKeyLess(key, oldestKey)) {
			oldestKey = key
			oldest = aggregation
		}
	}
	if oldest != nil {
		delete(s.alertAggregation, oldestKey)
	}
}

func (s *TelemetryServer) aggregationLimit() int {
	if s.maxAggregations > 0 {
		return s.maxAggregations
	}
	return defaultMaxAlertAggregations
}

func newAlertAggregation(now time.Time) *AlertAggregation {
	return &AlertAggregation{Count: 1, FirstSeen: now, LastSeen: now}
}

func boundedAlertKey(key AlertKey) AlertKey {
	key.EventType = boundedAggregationValue(key.EventType)
	key.Command = boundedAggregationValue(key.Command)
	key.Namespace = boundedAggregationValue(key.Namespace)
	key.PodName = boundedAggregationValue(key.PodName)
	key.ContainerID = boundedAggregationValue(key.ContainerID)
	key.Severity = boundedAggregationValue(key.Severity)
	return key
}

func boundedAggregationValue(value string) string {
	if len(value) <= maxAggregationValueBytes {
		return value
	}
	return strings.Clone(value[:maxAggregationValueBytes])
}

func alertKeyLess(left, right AlertKey) bool {
	leftValues := [...]string{left.EventType, left.Command, left.Namespace, left.PodName, left.ContainerID, left.Severity}
	rightValues := [...]string{right.EventType, right.Command, right.Namespace, right.PodName, right.ContainerID, right.Severity}
	for index := range leftValues {
		if leftValues[index] != rightValues[index] {
			return leftValues[index] < rightValues[index]
		}
	}
	return false
}
