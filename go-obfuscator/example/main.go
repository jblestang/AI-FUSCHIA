package main

import (
	"fmt"
	"os"
	"strings"
)

//gooverlay:file literals
// Representative license-gated CLI tool: strings, constants, and critical
// checks are obfuscated when built with gooverlay.

const (
	productVersion  = "2.4.1"
	minLicenseScore = 100
)

var defaultTier = "enterprise"

func formatBanner(host string) string {
	title := "SecureLicense Demo"
	return fmt.Sprintf("%s v%s tier=%s host=%s", title, productVersion, defaultTier, host)
}

func scoreLicenseKey(key string) int {
	normalized := strings.ToUpper(strings.TrimSpace(key))
	var score int
	for _, r := range normalized {
		if r != '-' {
			score += int(r)
		}
	}
	return score
}

//gooverlay:virtualize
func applyLicenseBonus(score int) int {
	return score + 42
}

func tierWeight(tier string) int {
	return len(tier)
}

func isLicensed(score int) bool {
	return score >= minLicenseScore
}

func main() {
	host := os.Args[0]
	for _, arg := range os.Args[1:] {
		host = arg
		break
	}

	licenseKey := "DEMO-ENT-2026"
	rawScore := scoreLicenseKey(licenseKey)
	finalScore := applyLicenseBonus(rawScore)

	fmt.Println(formatBanner(host))
	fmt.Println("license_score=", finalScore)
	fmt.Println("licensed=", isLicensed(finalScore))
	fmt.Println("tier_len=", tierWeight(defaultTier))
}
