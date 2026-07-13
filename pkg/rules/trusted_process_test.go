package rules

import "testing"

func TestYAMLClassifierRequiresExactTrustedExecutable(t *testing.T) {
	engine := &RuleEngine{rules: &SecurityRules{Commands: CommandRules{Trusted: []CommandRule{
		{Patterns: []string{"containerd"}},
	}}}}

	if !engine.isTrustedProcess("/usr/bin/containerd --config /etc/containerd.toml") {
		t.Fatal("exact trusted executable was rejected")
	}
	for _, command := range []string{"evil-containerd", "containerd-malicious", "sh containerd"} {
		if engine.isTrustedProcess(command) {
			t.Fatalf("spoofed command %q was trusted", command)
		}
	}
}
