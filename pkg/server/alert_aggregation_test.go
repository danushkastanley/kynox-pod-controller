package server

import (
	"strings"
	"testing"
)

func TestAlertAggregationIsBounded(t *testing.T) {
	server := &TelemetryServer{
		alertAggregation: make(map[AlertKey]*AlertAggregation),
		maxAggregations:  2,
	}

	for _, command := range []string{"one", "two", "three"} {
		server.aggregateAlert(AlertKey{EventType: "EXEC", Command: command}, "message")
	}

	if got := len(server.alertAggregation); got != 2 {
		t.Fatalf("aggregation size = %d, want 2", got)
	}
}

func TestAlertAggregationBoundsAttackerControlledKeyValues(t *testing.T) {
	server := &TelemetryServer{
		alertAggregation: make(map[AlertKey]*AlertAggregation),
		maxAggregations:  2,
	}
	server.aggregateAlert(AlertKey{Command: strings.Repeat("x", maxAggregationValueBytes+100)}, "message")

	for key := range server.alertAggregation {
		if len(key.Command) != maxAggregationValueBytes {
			t.Fatalf("bounded command length = %d, want %d", len(key.Command), maxAggregationValueBytes)
		}
	}
}
