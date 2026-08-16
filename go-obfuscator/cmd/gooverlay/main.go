package main

import (
	"fmt"
	"os"

	"github.com/ai-fuchsia/go-obfuscator/internal/driver"
)

func main() {
	if err := driver.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "gooverlay: %v\n", err)
		os.Exit(1)
	}
}
