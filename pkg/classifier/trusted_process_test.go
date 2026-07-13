package classifier

import "testing"

func TestDefaultClassifierRequiresExactTrustedExecutable(t *testing.T) {
	classifier := &EventClassifier{trustedProcesses: map[string]bool{"containerd": true}}

	if !classifier.isTrustedProcess("/usr/bin/containerd --config /etc/containerd.toml") {
		t.Fatal("exact trusted executable was rejected")
	}
	for _, command := range []string{"evil-containerd", "containerd-malicious", "sh containerd"} {
		if classifier.isTrustedProcess(command) {
			t.Fatalf("spoofed command %q was trusted", command)
		}
	}
}
