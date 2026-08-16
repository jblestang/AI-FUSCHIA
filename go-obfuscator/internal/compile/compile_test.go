package compile_test

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/ai-fuchsia/go-obfuscator/internal/compile"
)

func testConfig(seed string) compile.Config {
	return compile.Config{
		Seed:        seed,
		Literals:    true,
		Constants:   true,
		MBA:         true,
		ControlFlow: true,
	}
}

func TestRenamePrivateIdentifiers(t *testing.T) {
	const src = `package main

func main() {
	println(greet())
}

func greet() string {
	secret := "value"
	return secret
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	out, err := compile.RenameFile(compile.Config{Seed: "seed"}, "example.com/app", file, fset)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(out, "greet") {
		t.Fatalf("expected greet to be renamed, got:\n%s", out)
	}
	if strings.Contains(out, "secret") {
		t.Fatalf("expected secret to be renamed, got:\n%s", out)
	}
	if !strings.Contains(out, "func main") {
		t.Fatalf("expected main to remain, got:\n%s", out)
	}
}

func TestPrepareCompileExamplePipeline(t *testing.T) {
	t.Setenv("GOOVERLAY", "github.com/ai-fuchsia/go-obfuscator")
	t.Setenv("GOOVERLAY_ROOT", "/workspace/go-obfuscator")

	args := []string{
		"-o", "/tmp/test_pkg.a",
		"-p", "main",
		"-complete",
		"-pack",
		"/workspace/go-obfuscator/example/main.go",
	}
	cfg := testConfig("test")
	newArgs, err := compile.PrepareCompile(cfg, "github.com/ai-fuchsia/go-obfuscator/example", args)
	if err != nil {
		t.Fatal(err)
	}
	last := newArgs[len(newArgs)-1]
	data, err := os.ReadFile(last)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"gooverlay sample"`) {
		t.Fatalf("expected obfuscated literals")
	}
}

func TestPrepareCompileReplacesSourcePath(t *testing.T) {
	t.Setenv("GOOVERLAY", "github.com/ai-fuchsia/go-obfuscator")
	t.Setenv("GOOVERLAY_ROOT", "/workspace/go-obfuscator")

	args := []string{
		"-o", "/tmp/test_pkg.a",
		"-p", "main",
		"-complete",
		"-pack",
		"/workspace/go-obfuscator/example/main.go",
	}

	newArgs, err := compile.PrepareCompile(compile.Config{Seed: "seed"}, "github.com/ai-fuchsia/go-obfuscator/example", args)
	if err != nil {
		t.Fatal(err)
	}

	last := newArgs[len(newArgs)-1]
	if last == "/workspace/go-obfuscator/example/main.go" {
		t.Fatalf("expected rewritten source path, got original: %s", last)
	}
	if !strings.Contains(last, ".go") || last == "/workspace/go-obfuscator/example/main.go" {
		t.Fatalf("expected temp obfuscated file, got %s", last)
	}
	data, err := os.ReadFile(last)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "func greet") {
		t.Fatalf("expected greet to be renamed in obfuscated file")
	}
}
