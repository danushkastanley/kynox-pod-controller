package alert

import (
	"sort"
	"strings"
)

var slackMrkdwnEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
)

func escapeSlackMrkdwn(value string) string {
	return slackMrkdwnEscaper.Replace(value)
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
