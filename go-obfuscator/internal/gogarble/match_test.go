package gogarble_test

import (
	"testing"

	"github.com/ai-fuchsia/go-obfuscator/internal/gogarble"
)

func TestMatchPrefix(t *testing.T) {
	if !gogarble.Match("example.com/foo/bar", "example.com/foo") {
		t.Fatal("expected prefix match")
	}
}

func TestMatchGlob(t *testing.T) {
	if !gogarble.Match("example.com/foo/bar", "example.com/*") {
		t.Fatal("expected glob match")
	}
	if gogarble.Match("other.com/foo", "example.com/*") {
		t.Fatal("expected no match")
	}
}
