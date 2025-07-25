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
	log.Println("[INIT] Initializing alert dispatcher...")

	err := godotenv.Load()
	if err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
		return nil, fmt.Errorf("failed to load .env file: %v", err)
	}
	log.Println("[OK] .env file loaded successfully")

	config, err := LoadConfig()
	if err != nil {
		log.Printf("[ERROR] Failed to load alert config: %v", err)
		return nil, fmt.Errorf("failed to load alert config: %v", err)
	}
	slackStatus := "not configured"
	if config.SlackWebhookURL != "" {
		slackStatus = "configured"
	}
	log.Printf("[OK] Alert config loaded: EventTypes=%v, MinLevel=%s, SlackURL=%s",
		config.EventTypes, config.MinLevel, slackStatus)

	var notifiers []AlertNotifier

	// Initialize Slack notifier if configured
	if config.SlackWebhookURL != "" {
		notifiers = append(notifiers, NewSlackNotifier())
		log.Println("[OK] Slack notifier initialized")
	} else {
		log.Println("[WARN] Slack notifier not configured (no webhook URL)")
	}

	// Initialize Webhook notifier if configured
	if config.WebhookURL != "" {
		notifiers = append(notifiers, NewWebhookNotifier())
		log.Println("[OK] Webhook notifier initialized")
	} else {
		log.Println("[INFO] Webhook notifier not configured")
	}

	log.Printf("[START] Alert dispatcher initialized with %d notifiers", len(notifiers))

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
	log.Printf("[CHECK] Dispatch called with alert: EventType=%s, Level=%s", alert.EventType, alert.Level)

	// Check if we should alert on this event type
	if !d.config.ShouldAlertOnEvent(alert.EventType) {
		log.Printf("[SKIP] Skipping alert - event type %s not configured", alert.EventType)
		return nil
	}
	log.Printf("[OK] Event type %s is configured for alerting", alert.EventType)

	// Check if we should alert on this level
	if !d.config.ShouldAlertOnLevel(alert.Level) {
		log.Printf("[SKIP] Skipping alert - level %s not configured", alert.Level)
		return nil
	}
	log.Printf("[OK] Alert level %s is configured for alerting", alert.Level)

	// Generate alert ID if not set
	if alert.ID == "" {
		alert.ID = uuid.New().String()
	}

	// Set timestamp if not set
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}

	log.Printf("[LOCK] Acquiring read lock for notifiers")
	d.mu.RLock()
	defer d.mu.RUnlock()

	log.Printf("[FOUND] Found %d notifiers to check", len(d.notifiers))

	var errors []error
	var wg sync.WaitGroup

	for i, notifier := range d.notifiers {
		log.Printf("[CHECK] Checking notifier %d: %s, enabled=%t", i, notifier.Name(), notifier.IsEnabled())
		if !notifier.IsEnabled() {
			log.Printf("[SKIP] Skipping disabled notifier: %s", notifier.Name())
			continue
		}

		log.Printf("[SEND] Sending alert via %s", notifier.Name())
		wg.Add(1)
		go func(n AlertNotifier) {
			defer wg.Done()
			log.Printf("[START] Calling %s.Send()...", n.Name())
			if err := n.Send(alert); err != nil {
				log.Printf("[ERROR] Error sending alert via %s: %v", n.Name(), err)
				errors = append(errors, fmt.Errorf("%s: %v", n.Name(), err))
			} else {
				log.Printf("[OK] Successfully sent alert via %s", n.Name())
			}
		}(notifier)
	}

	log.Printf("[WAIT] Waiting for all notifiers to complete...")
	wg.Wait()
	log.Printf("[OK] All notifiers completed")

	if len(errors) > 0 {
		log.Printf("[ERROR] Some notifiers failed: %v", errors)
		return fmt.Errorf("failed to send alerts: %v", errors)
	}

	log.Printf("[SUCCESS] Alert dispatch completed successfully")
	return nil
}

// CreateAlert creates a new alert with the given parameters
func CreateAlert(level AlertLevel, title, message string, context map[string]string) *Alert {
	alert := &Alert{
		ID:               uuid.New().String(),
		Level:            level,
		Title:            title,
		Message:          message,
		Timestamp:        time.Now(),
		ProcessInfo:      make(map[string]string),
		NetworkInfo:      make(map[string]string),
		FileInfo:         make(map[string]string),
		SecurityInfo:     make(map[string]string),
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
