package command

import (
	"fmt"
	"strings"

	"github.com/kr/text"
)

// p215
func wrapAtLengthWithPadding(s string, pad int) string {
	wrapped := text.Wrap(s, maxLineLength-pad)
	lines := strings.Split(wrapped, "\n")
	for i, line := range lines {
		lines[i] = strings.Repeat(" ", pad) + line
	}
	return strings.Join(lines, "\n")
}

func wrapAtLength(s string) string {
	return wrapAtLengthWithPadding(s, 0)
}

// p296
func generateFlagWarnings(args []string) string {
	var trailingFlags []string
	for _, arg := range args {
		// "-" can be used where a file is expected to denote stdin.
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}

		isGlobalFlag := false
		trimmedArg, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		for _, flag := range globalFlags {
			if trimmedArg == flag {
				isGlobalFlag = true
			}
		}
		if isGlobalFlag {
			continue
		}

		trailingFlags = append(trailingFlags, arg)
	}

	if len(trailingFlags) > 0 {
		return fmt.Sprintf("Command flags must be provided before positional arguments. "+
			"The following arguments will not be parsed as flags: [%s]", strings.Join(trailingFlags, ","))
	} else {
		return ""
	}
}
