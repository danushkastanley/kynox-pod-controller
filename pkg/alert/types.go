package alert

import (
	"time"
)

// AlertLevel represents the severity of an alert
type AlertLevel string

const (
	AlertLevelInfo     AlertLevel = "INFO"
	AlertLevelWarning  AlertLevel = "WARNING"
	AlertLevelHigh     AlertLevel = "HIGH"
	AlertLevelCritical AlertLevel = "CRITICAL"
)

// Alert represents a security alert
type Alert struct {
	ID        string     `json:"id"`
	Level     AlertLevel `json:"level"`
	Title     string     `json:"title"`
	Message   string     `json:"message"`
	Timestamp time.Time  `json:"timestamp"`

	// Context information
	AgentID          string            `json:"agent_id"`
	NodeName         string            `json:"node_name"`
	PodName          string            `json:"pod_name"`
	ContainerID      string            `json:"container_id"`
	Namespace        string            `json:"namespace"`
	EventType        string            `json:"event_type"`
	Command          string            `json:"command,omitempty"`
	ProcessInfo      map[string]string `json:"process_info,omitempty"`
	NetworkInfo      map[string]string `json:"network_info,omitempty"`
	FileInfo         map[string]string `json:"file_info,omitempty"`
	SecurityInfo     map[string]string `json:"security_info,omitempty"`
	ContainerContext map[string]string `json:"container_context,omitempty"`
}

// AlertNotifier interface for different notification methods
type AlertNotifier interface {
	Name() string
	Send(alert *Alert) error
	IsEnabled() bool
}
