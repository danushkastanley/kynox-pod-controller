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
	Channel string       `json:"channel,omitempty"`
	Blocks  []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type   string       `json:"type"`
	Text   *slackText   `json:"text,omitempty"`
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
		logrus.Debug("[SKIP] Skipping Slack notification (not enabled)")
		return fmt.Errorf("slack notifications not enabled")
	}

	logrus.WithFields(logrus.Fields{
		"alert_level": alert.Level,
		"title":       alert.Title,
		"node":        alert.NodeName,
		"pod":         alert.PodName,
		"namespace":   alert.Namespace,
	}).Info("[SEND] Preparing Slack notification")

	// Create rich Slack message
	msg := s.createSlackMessage(alert)

	// Convert to JSON
	payload, err := json.Marshal(msg)
	if err != nil {
		logrus.WithError(err).Error("[ERROR] Failed to marshal Slack message")
		return fmt.Errorf("failed to marshal slack message: %v", err)
	}

	// Send to Slack
	logrus.Debug("[SEND] Sending message to Slack...")
	resp, err := http.Post(s.webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		logrus.WithError(err).Error("[ERROR] Failed to send Slack message")
		return fmt.Errorf("failed to send slack message: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logrus.WithField("status_code", resp.StatusCode).Error("[ERROR] Slack API returned error")
		return fmt.Errorf("slack API returned non-200 status: %d", resp.StatusCode)
	}

	logrus.WithFields(logrus.Fields{
		"alert_level": alert.Level,
		"title":       alert.Title,
	}).Info("[OK] Slack notification sent successfully")

	return nil
}

func (s *SlackNotifier) createSlackMessage(alert *Alert) slackMessage {
	// Text indicators based on alert level
	var indicator string
	switch alert.Level {
	case AlertLevelCritical:
		indicator = "[CRITICAL]"
	case AlertLevelHigh:
		indicator = "[HIGH]"
	case AlertLevelWarning:
		indicator = "[WARNING]"
	default:
		indicator = "[INFO]"
	}

	// Create header block
	headerText := fmt.Sprintf("%s *%s Alert:* %s", indicator, alert.Level, alert.Title)

	// Create context blocks
	var contextFields []slackField

	// Add target information (where the event occurred)
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

	// Add monitoring context if present
	if len(alert.ContainerContext) > 0 {
		var monitoringDetails []string

		// Check if we have monitoring agent info
		if monitoringAgent, exists := alert.ContainerContext["monitoring_agent"]; exists {
			monitoringDetails = append(monitoringDetails, fmt.Sprintf("• Detected by: %s", monitoringAgent))
		}
		if monitoringNode, exists := alert.ContainerContext["monitoring_node"]; exists {
			monitoringDetails = append(monitoringDetails, fmt.Sprintf("• Monitor node: %s", monitoringNode))
		}
		if targetContainer, exists := alert.ContainerContext["target_container_id"]; exists && targetContainer != "" {
			if len(targetContainer) > 12 {
				monitoringDetails = append(monitoringDetails, fmt.Sprintf("• Container ID: %s...", targetContainer[:12]))
			} else {
				monitoringDetails = append(monitoringDetails, fmt.Sprintf("• Container ID: %s", targetContainer))
			}
		}

		// Add other container context if not part of monitoring info
		for k, v := range alert.ContainerContext {
			if !strings.HasPrefix(k, "monitoring_") && !strings.HasPrefix(k, "target_") && v != "" {
				monitoringDetails = append(monitoringDetails, fmt.Sprintf("• %s: %s", k, v))
			}
		}

		if len(monitoringDetails) > 0 {
			contextFields = append(contextFields,
				slackField{Type: "mrkdwn", Text: "*Monitoring Context:*\n" + strings.Join(monitoringDetails, "\n")},
			)
		}
	}

	// Add process info if present
	if len(alert.ProcessInfo) > 0 {
		var processDetails []string
		for k, v := range alert.ProcessInfo {
			if v != "" && v != "0" { // Don't show empty or zero values for cleaner display
				processDetails = append(processDetails, fmt.Sprintf("• %s: %s", k, v))
			}
		}
		if len(processDetails) > 0 {
			contextFields = append(contextFields,
				slackField{Type: "mrkdwn", Text: "*Process Info:*\n" + strings.Join(processDetails, "\n")},
			)
		}
	}

	// Add network info if present and not empty
	if len(alert.NetworkInfo) > 0 {
		var networkDetails []string
		for k, v := range alert.NetworkInfo {
			if v != "" && v != "0" { // Don't show empty or zero values
				networkDetails = append(networkDetails, fmt.Sprintf("• %s: %s", k, v))
			}
		}
		if len(networkDetails) > 0 {
			contextFields = append(contextFields,
				slackField{Type: "mrkdwn", Text: "*Network Info:*\n" + strings.Join(networkDetails, "\n")},
			)
		}
	}

	// Add file info if present
	if len(alert.FileInfo) > 0 {
		var fileDetails []string
		for k, v := range alert.FileInfo {
			if v != "" {
				fileDetails = append(fileDetails, fmt.Sprintf("• %s: %s", k, v))
			}
		}
		if len(fileDetails) > 0 {
			contextFields = append(contextFields,
				slackField{Type: "mrkdwn", Text: "*File Info:*\n" + strings.Join(fileDetails, "\n")},
			)
		}
	}

	// Add security context
	if len(alert.SecurityInfo) > 0 {
		var securityDetails []string
		for k, v := range alert.SecurityInfo {
			if v != "" && k != "message" { // Skip message as it's already in the main text
				securityDetails = append(securityDetails, fmt.Sprintf("• %s: %s", k, v))
			}
		}
		if len(securityDetails) > 0 {
			contextFields = append(contextFields,
				slackField{Type: "mrkdwn", Text: "*Security Context:*\n" + strings.Join(securityDetails, "\n")},
			)
		}
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
