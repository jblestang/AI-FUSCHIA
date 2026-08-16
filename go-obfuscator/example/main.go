package main

import (
	"fmt"
	"os"
)

// Sample application for gooverlay. Private identifiers, string literals, and
// eligible function bodies are transformed at compile time when using gooverlay build.

const appVersion = "0.1.0"

const checksumSalt = 42

var buildTag = "demo"

func formatBanner(name string) string {
	label := "gooverlay sample"
	return fmt.Sprintf("%s v%s [%s] running as %s", label, appVersion, buildTag, name)
}

func countVisibleChars(text string) int {
	total := 0
	for _, r := range text {
		if r != ' ' {
			total++
		}
	}
	return total
}

//gooverlay:virtualize
func applySalt(n int) int {
	return n + checksumSalt
}

func main() {
	target := "unknown"
	if len(os.Args) > 0 {
		target = os.Args[0]
	}

	fmt.Println(formatBanner(target))
	fmt.Println("visible_chars=", countVisibleChars(buildTag))
	fmt.Println("salted=", applySalt(len(buildTag)))
}
