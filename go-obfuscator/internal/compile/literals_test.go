package compile_test

import (
	"bytes"
	"go/format"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/ai-fuchsia/go-obfuscator/internal/compile"
)

func formatFile(fset *token.FileSet, file interface{}) (string, error) {
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, file); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func TestObfuscateStringLiterals(t *testing.T) {
	const src = `package main

const greeting = "hello world"

func main() {
	println(greeting)
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	cfg := compile.Config{Seed: "test-seed", Literals: true}
	compile.ObfuscateLiteralsInFile(cfg, "example.com/app", fset, file)

	text, err := formatFile(fset, file)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(text, `"hello world"`) {
		t.Fatalf("expected string literal to be obfuscated, got:\n%s", text)
	}
	if !strings.Contains(text, "[]byte{") {
		t.Fatalf("expected encrypted byte slice, got:\n%s", text)
	}
}

func TestObfuscateIntegerConstants(t *testing.T) {
	const src = `package main

func mix(n int) int {
	return n + 42
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	cfg := compile.Config{Seed: "test-seed", Constants: true}
	compile.ObfuscateConstantsInFile(cfg, "example.com/app", file)

	text, err := formatFile(fset, file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "+ 42") || strings.Contains(text, "return 42") {
		t.Fatalf("expected integer literal to be obfuscated, got:\n%s", text)
	}
	if !strings.Contains(text, "__gooverlay_rasp") && !strings.Contains(text, "__gooverlay_ctab") {
		t.Fatalf("expected indexed constant table / RASP, got:\n%s", text)
	}
}

func TestMBAObfuscation(t *testing.T) {
	const src = `package main

func add(a, b int) int {
	return a + b
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	cfg := compile.Config{Seed: "test-seed", MBA: true}
	compile.ObfuscateMBAInFile(cfg, "example.com/app", file)

	text, err := formatFile(fset, file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "^") || !strings.Contains(text, "&") {
		t.Fatalf("expected MBA operators, got:\n%s", text)
	}
}

func TestFlattenControlFlow(t *testing.T) {
	const src = `package main

func work() int {
	a := 1
	b := 2
	return a + b
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	cfg := compile.Config{Seed: "test-seed", ControlFlow: true}
	compile.FlattenControlFlowInFile(cfg, "example.com/app", file)

	text, err := formatFile(fset, file)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(text, "switch") {
		t.Fatalf("expected flattened switch dispatcher, got:\n%s", text)
	}
	if strings.Count(text, "case ") < 2 {
		t.Fatalf("expected multiple state cases, got:\n%s", text)
	}
}

func TestLiteralObfuscationIsDeterministic(t *testing.T) {
	const src = `package main

func main() {
	println("stable")
}
`
	render := func(seed string) string {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "main.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		cfg := compile.Config{Seed: seed, Literals: true}
		compile.ObfuscateLiteralsInFile(cfg, "example.com/app", fset, file)
		out, err := formatFile(fset, file)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	a := render("same-seed")
	b := render("same-seed")
	if a != b {
		t.Fatalf("expected deterministic output for same seed")
	}

	c := render("other-seed")
	if a == c {
		t.Fatalf("expected different output for different seed")
	}
}

func TestConstantObfuscationIsDeterministic(t *testing.T) {
	const src = `package main

func f() int { return 99 }
`
	render := func(seed string) string {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "main.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		cfg := compile.Config{Seed: seed, Constants: true}
		compile.ObfuscateConstantsInFile(cfg, "example.com/app", file)
		out, err := formatFile(fset, file)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if render("seed-a") == render("seed-b") {
		t.Fatal("expected different constant obfuscation per seed")
	}
	if render("seed-a") != render("seed-a") {
		t.Fatal("expected deterministic constant obfuscation")
	}
}
