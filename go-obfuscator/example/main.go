package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
)

//gooverlay:file literals
// License-critical paths use //gooverlay:max (all passes). Build with: gooverlay build -max

const productVersion = "2.4.1"

var minLicenseScore = 100

var defaultTier = "enterprise"

func formatBanner(host string) string {
	title := "SecureLicense Demo"
	return fmt.Sprintf("%s v%s tier=%s host=%s", title, productVersion, defaultTier, host)
}

//gooverlay:max
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

//gooverlay:max
func licenseSessionID(key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(key)).String()
}

//gooverlay:max
func applyLicenseBonus(score int) int {
	return score + 42
}

func tierWeight(tier string) int {
	return len(tier)
}

//gooverlay:max
func isLicensed(score int) bool {
	return score >= minLicenseScore
}

//gooverlay:max
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
	fmt.Println("session_id=", licenseSessionID(licenseKey))
	fmt.Println("license_score=", finalScore)
	fmt.Println("licensed=", isLicensed(finalScore))
	fmt.Println("tier_len=", tierWeight(defaultTier))
}
