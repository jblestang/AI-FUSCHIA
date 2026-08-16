package hash_test

import (
	"strings"
	"testing"
	"unicode"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

func TestNameIsValidGoIdentifier(t *testing.T) {
	name := hash.Name("seed", "example.com/pkg", "countVisibleChars")
	if !unicode.IsLetter(rune(name[0])) {
		t.Fatalf("identifier must start with letter: %q", name)
	}
	for _, r := range name[1:] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			t.Fatalf("invalid identifier character %q in %q", r, name)
		}
	}
	if strings.Contains(name, "-") {
		t.Fatalf("identifier must not contain '-': %q", name)
	}
}

func TestBytesIsDeterministic(t *testing.T) {
	a := hash.Bytes("seed", "pkg", "literal:0", 8)
	b := hash.Bytes("seed", "pkg", "literal:0", 8)
	if string(a) != string(b) {
		t.Fatalf("expected deterministic bytes")
	}
	c := hash.Bytes("other", "pkg", "literal:0", 8)
	if string(a) == string(c) {
		t.Fatalf("expected different bytes for different seed")
	}
}
