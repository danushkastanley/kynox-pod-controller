package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"github.com/sirupsen/logrus"
)

type SlackNotifier struct {
	webhookURL string
	channel    string
	enabled    bool
}

type slackMessage struct {
	Channel string        `json:"channel,omitempty"`
	Blocks  []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type string      `json:"type"`
	Text *slackText  `json:"text,omitempty"`
	Fields []slackField `json:"fields,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackField struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func NewSlackNotifier() *SlackNotifier {
	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	channel := os.Getenv("SLACK_CHANNEL")
	
	return &SlackNotifier{
		webhookURL: webhookURL,
		channel:    channel,
		enabled:    webhookURL != "",
	}
}

func (s *SlackNotifier) Name() string {
	return "slack"
}

func (s *SlackNotifier) IsEnabled() bool {
	return s.enabled
}

func (s *SlackNotifier) Send(alert *Alert) error {
	if !s.enabled {
		logrus.Debug("⏭️ Skipping Slack notification (not enabled)")
		return fmt.Errorf("slack notifications not enabled")
	}

	logrus.WithFields(logrus.Fields{
		"alert_level": alert.Level,
		"title": alert.Title,
		"node": alert.NodeName,
		"pod": alert.PodName,
		"namespace": alert.Namespace,
	}).Info("📤 Preparing Slack notification")

	// Create rich Slack message
	msg := s.createSlackMessage(alert)

	// Convert to JSON
	payload, err := json.Marshal(msg)
	if err != nil {
		logrus.WithError(err).Error("❌ Failed to marshal Slack message")
		return fmt.Errorf("failed to marshal slack message: %v", err)
	}

	// Send to Slack
	logrus.Debug("📡 Sending message to Slack...")
	resp, err := http.Post(s.webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		logrus.WithError(err).Error("❌ Failed to send Slack message")
		return fmt.Errorf("failed to send slack message: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logrus.WithField("status_code", resp.StatusCode).Error("❌ Slack API returned error")
		return fmt.Errorf("slack API returned non-200 status: %d", resp.StatusCode)
	}

	logrus.WithFields(logrus.Fields{
		"alert_level": alert.Level,
		"title": alert.Title,
	}).Info("✅ Slack notification sent successfully")

	return nil
}

func (s *SlackNotifier) createSlackMessage(alert *Alert) slackMessage {
	// Color coding based on alert level
	var emoji string
	switch alert.Level {
	case AlertLevelCritical:
		emoji = "🚨"
	case AlertLevelWarning:
		emoji = "⚠️"
	default:
		emoji = "ℹ️"
	}

	// Create header block
	headerText := fmt.Sprintf("%s *%s Alert:* %s", emoji, alert.Level, alert.Title)
	
	// Create context blocks
	var contextFields []slackField
	
	// Add basic info
	contextFields = append(contextFields,
		slackField{Type: "mrkdwn", Text: fmt.Sprintf("*Node:* %s", alert.NodeName)},
		slackField{Type: "mrkdwn", Text: fmt.Sprintf("*Pod:* %s", alert.PodName)},
		slackField{Type: "mrkdwn", Text: fmt.Sprintf("*Namespace:* %s", alert.Namespace)},
		slackField{Type: "mrkdwn", Text: fmt.Sprintf("*Event Type:* %s", alert.EventType)},
	)

	// Add command if present
	if alert.Command != "" {
		contextFields = append(contextFields,
			slackField{Type: "mrkdwn", Text: fmt.Sprintf("*Command:* `%s`", alert.Command)},
		)
	}

	// Add container context if present
	if len(alert.ContainerContext) > 0 {
		var containerDetails []string
		for k, v := range alert.ContainerContext {
			containerDetails = append(containerDetails, fmt.Sprintf("• %s: %s", k, v))
		}
		contextFields = append(contextFields,
			slackField{Type: "mrkdwn", Text: "*Container Info:*\n" + strings.Join(containerDetails, "\n")},
		)
	}

	// Add process info if present
	if len(alert.ProcessInfo) > 0 {
		var processDetails []string
		for k, v := range alert.ProcessInfo {
			processDetails = append(processDetails, fmt.Sprintf("• %s: %s", k, v))
		}
		contextFields = append(contextFields,
			slackField{Type: "mrkdwn", Text: "*Process Info:*\n" + strings.Join(processDetails, "\n")},
		)
	}

	// Add network info if present
	if len(alert.NetworkInfo) > 0 {
		var networkDetails []string
		for k, v := range alert.NetworkInfo {
			networkDetails = append(networkDetails, fmt.Sprintf("• %s: %s", k, v))
		}
		contextFields = append(contextFields,
			slackField{Type: "mrkdwn", Text: "*Network Info:*\n" + strings.Join(networkDetails, "\n")},
		)
	}

	return slackMessage{
		Channel: s.channel,
		Blocks: []slackBlock{
			{
				Type: "header",
				Text: &slackText{
					Type: "plain_text",
					Text: headerText,
				},
			},
			{
				Type: "section",
				Text: &slackText{
					Type: "mrkdwn",
					Text: alert.Message,
				},
			},
			{
				Type:   "section",
				Fields: contextFields,
			},
		},
	}
}
