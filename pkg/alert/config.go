package alert

import (
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// Config holds the alert configuration
type Config struct {
	// Slack configuration
	SlackWebhookURL string
	SlackChannel    string

	// Webhook configuration
	WebhookURL string

	// Alert filtering
	EventTypes []string
	MinLevel   AlertLevel
	RateLimit  int
}

// LoadConfig loads the alert configuration from environment variables
func LoadConfig() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		logrus.Warn("No .env file found")
	}

	config := &Config{
		SlackWebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
		SlackChannel:    os.Getenv("SLACK_CHANNEL"),
		WebhookURL:      os.Getenv("ALERT_WEBHOOK_URL"),
		MinLevel:        AlertLevel(getEnvWithDefault("ALERT_MIN_LEVEL", string(AlertLevelWarning))),
	}

	// Parse event types
	if types := os.Getenv("ALERT_EVENT_TYPES"); types != "" {
		config.EventTypes = strings.Split(types, ",")
		// Trim spaces
		for i := range config.EventTypes {
			config.EventTypes[i] = strings.TrimSpace(config.EventTypes[i])
		}
	}

	// Parse rate limit
	if limit := os.Getenv("ALERT_RATE_LIMIT"); limit != "" {
		if val, err := strconv.Atoi(limit); err == nil {
			config.RateLimit = val
		}
	}

	return config, nil
}

// ShouldAlertOnEvent checks if we should alert on a given event type
func (c *Config) ShouldAlertOnEvent(eventType string) bool {
	if len(c.EventTypes) == 0 {
		return true
	}
	for _, t := range c.EventTypes {
		if t == eventType {
			return true
		}
	}
	return false
}

// ShouldAlertOnLevel checks if we should alert on a given level
func (c *Config) ShouldAlertOnLevel(level AlertLevel) bool {
	switch c.MinLevel {
	case AlertLevelInfo:
		return true
	case AlertLevelWarning:
		return level == AlertLevelWarning || level == AlertLevelHigh || level == AlertLevelCritical
	case AlertLevelHigh:
		return level == AlertLevelHigh || level == AlertLevelCritical
	case AlertLevelCritical:
		return level == AlertLevelCritical
	default:
		return level == AlertLevelWarning || level == AlertLevelHigh || level == AlertLevelCritical
	}
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
