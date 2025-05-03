package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type WebhookNotifier struct {
	webhookURL string
	enabled    bool
}

func NewWebhookNotifier() *WebhookNotifier {
	webhookURL := os.Getenv("ALERT_WEBHOOK_URL")
	return &WebhookNotifier{
		webhookURL: webhookURL,
		enabled:    webhookURL != "",
	}
}

func (w *WebhookNotifier) Name() string {
	return "webhook"
}

func (w *WebhookNotifier) IsEnabled() bool {
	return w.enabled
}

func (w *WebhookNotifier) Send(alert *Alert) error {
	if !w.enabled {
		return fmt.Errorf("webhook notifications not enabled")
	}

	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %v", err)
	}

	resp, err := http.Post(w.webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to send webhook: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("webhook returned non-200 status: %d", resp.StatusCode)
	}

	return nil
}
