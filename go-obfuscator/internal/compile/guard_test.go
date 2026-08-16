package compile_test

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/ai-fuchsia/go-obfuscator/internal/compile"
)

func TestSecurityGuardsInjected(t *testing.T) {
	const src = `package main

func work() int {
	return 1
}

func main() {
	println(work())
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := compile.Config{Seed: "guard-test", Tamper: true, AntiDebug: true, Junk: false, Opaque: false}
	compile.InjectSecurityGuardsInFile(cfg, "example.com/app", file)

	text, err := formatFile(fset, file)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		"__gooverlay_integrity",
		"__gooverlay_antidebug",
		"__gooverlay_report_tamper",
		"TracerPid:",
		"/proc/self/status",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("expected security runtime %q in:\n%s", needle, text)
		}
	}
	if !strings.Contains(text, "if !__gooverlay_integrity") && !strings.Contains(text, "__gooverlay_integrity(") {
		t.Fatalf("expected tamper check in function body:\n%s", text)
	}
}
