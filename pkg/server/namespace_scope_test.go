package server

import (
	"testing"
	"time"

	"pod-controller/pkg/alert"
	"pod-controller/pkg/classifier"
	"pod-controller/pkg/filter"
	pb "pod-controller/pkg/telemetry"

	"golang.org/x/time/rate"
)

type countingClassifier struct{ calls int }

func (c *countingClassifier) ClassifyEvent(*pb.SecurityEvent) (classifier.Severity, string) {
	c.calls++
	return classifier.SeverityLow, "test"
}

func newScopeTestServer(t *testing.T, monitorNamespaces string) (*TelemetryServer, *countingClassifier) {
	t.Helper()
	t.Setenv("MONITOR_NAMESPACES", monitorNamespaces)

	dispatcher, err := alert.NewAlertDispatcher()
	if err != nil {
		t.Fatalf("create alert dispatcher: %v", err)
	}
	counter := &countingClassifier{}
	return &TelemetryServer{
		agents:           make(map[string]*ConnectedAgent),
		classifier:       counter,
		alertLimiter:     rate.NewLimiter(rate.Every(time.Second), 1),
		alerter:          dispatcher,
		namespaceFilter:  filter.NewNamespaceFilter(),
		eventCounts:      make(map[string]int64),
		severityCounts:   make(map[string]int64),
		alertAggregation: make(map[AlertKey]*AlertAggregation),
		maxAggregations:  defaultMaxAlertAggregations,
	}, counter
}

func scopedEvent(namespace string) *pb.SecurityEvent {
	context := map[string]string{"pod_name": "unknown"}
	if namespace != "" {
		context["namespace"] = namespace
	}
	return &pb.SecurityEvent{EventType: pb.EventType_EXEC, Command: "sh", ContainerContext: context}
}

func TestProcessEventAlwaysProcessesUnattributedEvents(t *testing.T) {
	server, counter := newScopeTestServer(t, "payments")
	agent := &ConnectedAgent{AgentID: "agent-a", PodName: "pod-agent-a"}

	for _, namespace := range []string{"unknown", ""} {
		if err := server.processEvent(scopedEvent(namespace), agent); err != nil {
			t.Fatalf("processEvent(%q) returned error: %v", namespace, err)
		}
	}

	if counter.calls != 2 {
		t.Fatalf("classified %d unattributed events, want 2", counter.calls)
	}
	if got := server.filteredEvents.Load(); got != 0 {
		t.Fatalf("filtered %d unattributed events, want 0", got)
	}
}

func TestProcessEventFiltersPodEventsOutsideMonitoredNamespaces(t *testing.T) {
	server, counter := newScopeTestServer(t, "payments")
	agent := &ConnectedAgent{AgentID: "agent-a", PodName: "pod-agent-a"}

	for _, namespace := range []string{"payments", "marketing"} {
		if err := server.processEvent(scopedEvent(namespace), agent); err != nil {
			t.Fatalf("processEvent(%q) returned error: %v", namespace, err)
		}
	}

	if counter.calls != 1 {
		t.Fatalf("classified %d events, want 1 (payments only)", counter.calls)
	}
	if got := server.filteredEvents.Load(); got != 1 {
		t.Fatalf("filtered %d events, want 1 (marketing)", got)
	}
}
