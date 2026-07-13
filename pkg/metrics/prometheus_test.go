package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestUntrustedMetricDimensionsAreLabelFree(t *testing.T) {
	metrics := NewMetrics()
	metrics.RecordEvent("EXEC", "HIGH", "attacker-namespace")
	metrics.RecordAgentConnect("attacker-node")
	metrics.RecordHeartbeat("attacker-agent", "attacker-node")

	if got := testutil.ToFloat64(metrics.EventsByNamespace); got != 1 {
		t.Fatalf("namespace-context count = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.AgentsConnected); got != 1 {
		t.Fatalf("connected agents = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.AgentHeartbeats); got != 1 {
		t.Fatalf("heartbeats = %v, want 1", got)
	}
}
