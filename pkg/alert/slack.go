package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

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
		logrus.Debug("⏭️ Skipping Slack notification (not enabled)")
		return fmt.Errorf("slack notifications not enabled")
	}

	logrus.WithFields(logrus.Fields{
		"alert_level": alert.Level,
		"title":       alert.Title,
		"node":        alert.NodeName,
		"pod":         alert.PodName,
		"namespace":   alert.Namespace,
	}).Info("📤 Preparing Slack notification")

	// Create rich Slack message
	msg := s.createSlackMessage(alert)

	// Convert to JSON
	payload, err := json.Marshal(msg)
	if err != nil {
		logrus.WithError(err).Error("❌ Failed to marshal Slack message")
		return fmt.Errorf("failed to marshal slack message: %v", err)
	}

	// Check message size (Slack has a 40KB limit)
	if len(payload) > 35000 { // Leave some buffer
		logrus.WithField("size_bytes", len(payload)).Warn("⚠️ Slack message too large, truncating")
		// Create a simplified message
		msg := s.createSimplifiedSlackMessage(alert)
		var err error
		payload, err = json.Marshal(msg)
		if err != nil {
			logrus.WithError(err).Error("❌ Failed to marshal simplified Slack message")
			return fmt.Errorf("failed to marshal simplified slack message: %v", err)
		}
	}

	// Send to Slack with retry logic for rate limiting
	logrus.Debug("📡 Sending message to Slack...")

	maxRetries := 5 // Increased retries
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			// More aggressive backoff for Slack rate limits
			waitTime := time.Duration(5+retry*retry*2) * time.Second
			logrus.WithField("retry", retry).WithField("wait_seconds", waitTime.Seconds()).Info("⏳ Retrying Slack notification after wait")
			time.Sleep(waitTime)
		}

		resp, err := http.Post(s.webhookURL, "application/json", bytes.NewBuffer(payload))
		if err != nil {
			lastErr = fmt.Errorf("failed to send slack message: %v", err)
			logrus.WithError(err).WithField("retry", retry).Warn("⚠️ Failed to send Slack message, will retry")
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			// Success!
			break
		} else if resp.StatusCode == 429 {
			// Rate limited, retry with longer backoff
			lastErr = fmt.Errorf("slack API rate limited (status: %d)", resp.StatusCode)
			logrus.WithField("status_code", resp.StatusCode).WithField("retry", retry).Warn("⚠️ Slack API rate limited, will retry with longer wait")
			continue
		} else {
			// Other error, don't retry
			lastErr = fmt.Errorf("slack API returned non-200 status: %d", resp.StatusCode)
			logrus.WithField("status_code", resp.StatusCode).Error("❌ Slack API returned error")
			return lastErr
		}
	}

	if lastErr != nil {
		logrus.WithError(lastErr).Error("❌ Failed to send Slack message after all retries")
		return lastErr
	}

	logrus.WithFields(logrus.Fields{
		"alert_level": alert.Level,
		"title":       alert.Title,
	}).Info("✅ Slack notification sent successfully")

	return nil
}

func (s *SlackNotifier) createSlackMessage(alert *Alert) slackMessage {
	// Color coding based on alert level
	var emoji string
	switch alert.Level {
	case AlertLevelCritical:
		emoji = "🚨"
	case AlertLevelHigh:
		emoji = "🔴"
	case AlertLevelWarning:
		emoji = "⚠️"
	default:
		emoji = "ℹ️"
	}

	// Create header block
	headerText := fmt.Sprintf("%s *%s Alert:* %s", emoji, alert.Level, alert.Title)

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

	// Add MITRE ATT&CK information
	if len(alert.AttackTechniques) > 0 {
		var techniqueDetails []string
		for _, technique := range alert.AttackTechniques {
			detail := fmt.Sprintf("• %s (%s) - %s [Confidence: %.0f%%]",
				technique.TechniqueName,
				technique.TechniqueID,
				technique.Tactic,
				technique.Confidence*100)
			techniqueDetails = append(techniqueDetails, detail)
		}
		contextFields = append(contextFields,
			slackField{Type: "mrkdwn", Text: "*🎯 MITRE ATT&CK Techniques:*\n" + strings.Join(techniqueDetails, "\n")},
		)
	}

	// Add CVE information
	if len(alert.CVEReferences) > 0 {
		var cveDetails []string
		for _, cve := range alert.CVEReferences {
			detail := fmt.Sprintf("• %s (CVSS: %.1f) - %s - %s",
				cve.CVEID,
				cve.Score,
				cve.Severity,
				cve.Description)
			cveDetails = append(cveDetails, detail)
		}
		contextFields = append(contextFields,
			slackField{Type: "mrkdwn", Text: "*🔍 CVE References:*\n" + strings.Join(cveDetails, "\n")},
		)
	}

	// Add Threat Intelligence information
	if alert.ThreatIntel != nil {
		var threatDetails []string

		if len(alert.ThreatIntel.ThreatActors) > 0 {
			threatDetails = append(threatDetails, fmt.Sprintf("• Threat Actors: %s", strings.Join(alert.ThreatIntel.ThreatActors, ", ")))
		}
		if len(alert.ThreatIntel.Campaigns) > 0 {
			threatDetails = append(threatDetails, fmt.Sprintf("• Campaigns: %s", strings.Join(alert.ThreatIntel.Campaigns, ", ")))
		}
		if len(alert.ThreatIntel.Malware) > 0 {
			threatDetails = append(threatDetails, fmt.Sprintf("• Malware: %s", strings.Join(alert.ThreatIntel.Malware, ", ")))
		}
		if len(alert.ThreatIntel.IOCs) > 0 {
			threatDetails = append(threatDetails, fmt.Sprintf("• IOCs: %s", strings.Join(alert.ThreatIntel.IOCs, ", ")))
		}

		if len(threatDetails) > 0 {
			contextFields = append(contextFields,
				slackField{Type: "mrkdwn", Text: "*🕵️ Threat Intelligence:*\n" + strings.Join(threatDetails, "\n")},
			)
		}
	}

	// Add Custom Classifications
	if len(alert.Classifications) > 0 {
		var classificationDetails []string
		for _, classification := range alert.Classifications {
			detail := fmt.Sprintf("• %s: %s", classification.Framework, classification.Category)
			if classification.Subcategory != "" {
				detail += fmt.Sprintf(" - %s", classification.Subcategory)
			}
			detail += fmt.Sprintf(" [Confidence: %.0f%%]", classification.Confidence*100)
			classificationDetails = append(classificationDetails, detail)
		}
		contextFields = append(contextFields,
			slackField{Type: "mrkdwn", Text: "*📊 Classifications:*\n" + strings.Join(classificationDetails, "\n")},
		)
	}

	return slackMessage{
		Channel: s.channel,
		Blocks: []slackBlock{
			{
				Type: "section",
				Text: &slackText{
					Type: "mrkdwn",
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

func (s *SlackNotifier) createSimplifiedSlackMessage(alert *Alert) slackMessage {
	// Color coding based on alert level
	var emoji string
	switch alert.Level {
	case AlertLevelCritical:
		emoji = "🚨"
	case AlertLevelHigh:
		emoji = "🔴"
	case AlertLevelWarning:
		emoji = "⚠️"
	default:
		emoji = "ℹ️"
	}

	// Create simplified header text
	headerText := fmt.Sprintf("%s *%s Alert:* %s", emoji, alert.Level, alert.Title)

	// Create minimal context fields - only the most important info
	var contextFields []slackField

	// Add basic information
	contextFields = append(contextFields,
		slackField{Type: "mrkdwn", Text: fmt.Sprintf("*Node:* %s", alert.NodeName)},
		slackField{Type: "mrkdwn", Text: fmt.Sprintf("*Pod:* %s", alert.PodName)},
		slackField{Type: "mrkdwn", Text: fmt.Sprintf("*Event:* %s", alert.EventType)},
	)

	// Add command if present (but truncate if too long)
	if alert.Command != "" {
		command := alert.Command
		if len(command) > 100 {
			command = command[:97] + "..."
		}
		contextFields = append(contextFields,
			slackField{Type: "mrkdwn", Text: fmt.Sprintf("*Command:* `%s`", command)},
		)
	}

	return slackMessage{
		Channel: s.channel,
		Blocks: []slackBlock{
			{
				Type: "section",
				Text: &slackText{
					Type: "mrkdwn",
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
