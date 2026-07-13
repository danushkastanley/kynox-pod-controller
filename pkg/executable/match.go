package executable

import (
	"path/filepath"
	"strings"
)

// Matches reports whether command invokes exactly the trusted executable.
// Paths and arguments are accepted, but substrings and later arguments are not.
func Matches(command, trusted string) bool {
	commandName := name(command)
	trustedName := name(trusted)
	return commandName != "" && trustedName != "" && commandName == trustedName
}

func name(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return filepath.Base(fields[0])
}
