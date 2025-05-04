package alert

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

// AlertDispatcher handles the distribution of alerts to various notifiers
type AlertDispatcher struct {
	notifiers []AlertNotifier
	config    *Config
	mu        sync.RWMutex
}

// NewAlertDispatcher creates a new AlertDispatcher with the specified notifiers
func NewAlertDispatcher() (*AlertDispatcher, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load .env file: %v", err)
	}

	config, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load alert config: %v", err)
	}

	var notifiers []AlertNotifier

	// Initialize Slack notifier if configured
	if config.SlackWebhookURL != "" {
		notifiers = append(notifiers, NewSlackNotifier())
	}

	// Initialize Webhook notifier if configured
	if config.WebhookURL != "" {
		notifiers = append(notifiers, NewWebhookNotifier())
	}

	return &AlertDispatcher{
		notifiers: notifiers,
		config:    config,
	}, nil
}

// AddNotifier adds a new notifier to the dispatcher
func (d *AlertDispatcher) AddNotifier(notifier AlertNotifier) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notifiers = append(d.notifiers, notifier)
}

// Dispatch sends an alert to all enabled notifiers
func (d *AlertDispatcher) Dispatch(alert *Alert) error {
	// Check if we should alert on this event type
	if !d.config.ShouldAlertOnEvent(alert.EventType) {
		return nil
	}

	// Check if we should alert on this level
	if !d.config.ShouldAlertOnLevel(alert.Level) {
		return nil
	}

	// Generate alert ID if not set
	if alert.ID == "" {
		alert.ID = uuid.New().String()
	}

	// Set timestamp if not set
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	var errors []error
	var wg sync.WaitGroup

	for _, notifier := range d.notifiers {
		if !notifier.IsEnabled() {
			continue
		}

		wg.Add(1)
		go func(n AlertNotifier) {
			defer wg.Done()
			if err := n.Send(alert); err != nil {
				log.Printf("Error sending alert via %s: %v", n.Name(), err)
				errors = append(errors, fmt.Errorf("%s: %v", n.Name(), err))
			}
		}(notifier)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("failed to send alerts: %v", errors)
	}

	return nil
}

// CreateAlert creates a new alert with the given parameters
func CreateAlert(level AlertLevel, title, message string, context map[string]string) *Alert {
	alert := &Alert{
		ID:              uuid.New().String(),
		Level:           level,
		Title:           title,
		Message:         message,
		Timestamp:       time.Now(),
		ProcessInfo:     make(map[string]string),
		NetworkInfo:     make(map[string]string),
		FileInfo:        make(map[string]string),
		SecurityInfo:    make(map[string]string),
		ContainerContext: make(map[string]string),
	}

	// Add context information if provided
	if context != nil {
		if v, ok := context["agent_id"]; ok {
			alert.AgentID = v
		}
		if v, ok := context["node_name"]; ok {
			alert.NodeName = v
		}
		if v, ok := context["pod_name"]; ok {
			alert.PodName = v
		}
		if v, ok := context["container_id"]; ok {
			alert.ContainerID = v
		}
		if v, ok := context["namespace"]; ok {
			alert.Namespace = v
		}
		if v, ok := context["event_type"]; ok {
			alert.EventType = v
		}
		if v, ok := context["command"]; ok {
			alert.Command = v
		}

		// Process additional info maps
		for k, v := range context {
			switch {
			case k[:4] == "proc":
				alert.ProcessInfo[k[5:]] = v
			case k[:3] == "net":
				alert.NetworkInfo[k[4:]] = v
			case k[:4] == "file":
				alert.FileInfo[k[5:]] = v
			case k[:3] == "sec":
				alert.SecurityInfo[k[4:]] = v
			case k[:4] == "cont":
				alert.ContainerContext[k[5:]] = v
			}
		}
	}

	return alert
}
