package compile_test

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/ai-fuchsia/go-obfuscator/internal/compile"
)

func TestVirtualizeSimpleFunction(t *testing.T) {
	const src = `package main

const salt = 42

func apply(n int) int {
	return n + salt
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	cfg := compile.Config{Seed: "vm-test", Virtualize: true, Junk: false, Opaque: false, Constants: false, MBA: false}
	compile.RenameFile(cfg, "example.com/app", file, fset)
	compile.VirtualizeFunctionsInFile(cfg, "example.com/app", file)

	text, err := formatFile(fset, file)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(text, "return n + salt") && strings.Contains(text, "return o") == false {
		t.Fatalf("expected virtualization to replace body, got:\n%s", text)
	}
	if !strings.Contains(text, "case 255:") {
		t.Fatalf("expected VM interpreter switch, got:\n%s", text)
	}
}
