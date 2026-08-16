package execproxy

import (
	"fmt"
	"os"
	"syscall"
)

// Forward runs the real toolchain binary at toolPath with the given arguments.
func Forward(toolPath string, args []string) error {
	argv := append([]string{toolPath}, args...)
	return syscall.Exec(toolPath, argv, os.Environ())
}

// ForwardFirstArg runs the binary named in args[0] with the remaining arguments.
func ForwardFirstArg(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing tool path")
	}
	return Forward(args[0], args[1:])
}
