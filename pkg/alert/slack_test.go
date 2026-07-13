package alert

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSlackMessageEscapesUntrustedMrkdwn(t *testing.T) {
	notifier := &SlackNotifier{}
	message := notifier.createSlackMessage(&Alert{
		Level:     AlertLevelHigh,
		Title:     "Alert",
		Message:   "notify <!channel> & <@U123>",
		NodeName:  "<node>",
		PodName:   "pod",
		Namespace: "namespace",
		EventType: "EXEC",
		Command:   "run <!here>",
		ProcessInfo: map[string]string{
			"command": "<@U456>",
		},
	})

	for _, block := range message.Blocks {
		if block.Text != nil && strings.Contains(block.Text.Text, "<!") {
			t.Fatalf("unescaped mrkdwn in block text: %q", block.Text.Text)
		}
		for _, field := range block.Fields {
			if strings.Contains(field.Text, "<!") || strings.Contains(field.Text, "<@") {
				t.Fatalf("unescaped mrkdwn in field: %q", field.Text)
			}
		}
	}
	if got := message.Blocks[1].Text.Text; !strings.Contains(got, "&lt;!channel&gt; &amp; &lt;@U123&gt;") {
		t.Fatalf("escaped message = %q", got)
	}
}

func TestSlackNotifierUsesBoundedHTTPTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	notifier := &SlackNotifier{
		webhookURL: server.URL,
		enabled:    true,
		client:     &http.Client{Timeout: 20 * time.Millisecond},
	}
	err := notifier.Send(&Alert{Level: AlertLevelHigh, Title: "Alert", Message: "message"})
	if err == nil || !strings.Contains(err.Error(), "Client.Timeout") {
		t.Fatalf("timeout error = %v", err)
	}
}
