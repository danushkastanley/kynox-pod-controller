package executable

import "testing"

func TestMatchesExactExecutable(t *testing.T) {
	tests := []struct {
		name    string
		command string
		trusted string
		want    bool
	}{
		{name: "exact", command: "containerd", trusted: "containerd", want: true},
		{name: "absolute path", command: "/usr/bin/containerd --config /etc/containerd.toml", trusted: "containerd", want: true},
		{name: "trusted path", command: "containerd", trusted: "/usr/bin/containerd", want: true},
		{name: "prefix spoof", command: "containerd-malicious", trusted: "containerd", want: false},
		{name: "suffix spoof", command: "evil-containerd", trusted: "containerd", want: false},
		{name: "later argument", command: "sh containerd", trusted: "containerd", want: false},
		{name: "case differs", command: "Containerd", trusted: "containerd", want: false},
		{name: "empty", command: "", trusted: "containerd", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Matches(test.command, test.trusted); got != test.want {
				t.Fatalf("Matches(%q, %q) = %v, want %v", test.command, test.trusted, got, test.want)
			}
		})
	}
}
