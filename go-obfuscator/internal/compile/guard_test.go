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
	cfg := compile.Config{Seed: "guard-test", Tamper: true, AntiDebug: true, AntiEmulation: true, Junk: false, Opaque: false}
	compile.InjectSecurityGuardsInFile(cfg, "example.com/app", file)

	text, err := formatFile(fset, file)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"__gooverlay_integrity",
		"__gooverlay_antidebug",
		"__gooverlay_antiemulation",
		"__gooverlay_report_tamper",
		"TracerPid:",
		"/proc/self/status",
		"/proc/cpuinfo",
		"qemu_fw_cfg",
		"QEMU_ENV",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("cleartext security marker %q should be hidden:\n%s", forbidden, text)
		}
	}
	if !strings.Contains(text, "func o") {
		t.Fatalf("expected hashed guard symbols in:\n%s", text)
	}
	if !strings.Contains(text, "os.Exit") {
		t.Fatalf("expected inlined guard exit in function body:\n%s", text)
	}
}
