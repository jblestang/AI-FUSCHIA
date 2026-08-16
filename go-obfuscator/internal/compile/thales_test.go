package compile_test

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/ai-fuchsia/go-obfuscator/internal/compile"
)

func TestMBAOpaqueAndConstantTable(t *testing.T) {
	const src = `package main

func f() int {
	x := 1
	y := 2
	return x + y + 10
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := compile.Config{Seed: "thales-test", Constants: true, Opaque: true, MBA: false, Junk: false}
	compile.ObfuscateConstantsInFile(cfg, "example.com/app", file)
	compile.InjectOpaqueInFile(cfg, "example.com/app", file)

	text, err := formatFile(fset, file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "__gooverlay_ctab") {
		t.Fatalf("expected indexed constant table, got:\n%s", text)
	}
	if !strings.Contains(text, "__gooverlay_rasp") {
		t.Fatalf("expected RASP agent, got:\n%s", text)
	}
	if !strings.Contains(text, "*") || !strings.Contains(text, "==") {
		t.Fatalf("expected MBA multiplication opaque predicate, got:\n%s", text)
	}
}

func TestVirtualizeRunsCorrectly(t *testing.T) {
	const src = `package main

const salt = 42

func apply(n int) int {
	return n + salt
}

func main() {
	_ = apply(4)
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := compile.Config{
		Seed: "vm-exec", Virtualize: true,
		Constants: false, MBA: false, Junk: false, Opaque: false,
	}
	compile.VirtualizeFunctionsInFile(cfg, "example.com/app", file)
	text, err := formatFile(fset, file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "case 0:") {
		t.Fatalf("expected fictional NOP case, got:\n%s", text)
	}
	if !strings.Contains(text, "chkStack") {
		t.Fatalf("expected checksum shadow stack, got:\n%s", text)
	}
}
