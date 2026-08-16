package compile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestEachPassFormatsExample(t *testing.T) {
	t.Setenv("GOOVERLAY", "github.com/ai-fuchsia/go-obfuscator")
	t.Setenv("GOOVERLAY_ROOT", "/workspace/go-obfuscator")

	path := "/workspace/go-obfuscator/example/main.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Seed: "test", Literals: true, Constants: true, MBA: true, ControlFlow: true, Junk: false, Opaque: false}
	pkg := "github.com/ai-fuchsia/go-obfuscator/example"

	renamer := newRenamer(cfg, pkg)
	renamer.collectPackageNames(file)
	ast.Walk(renamer, file)
	if _, err := formatFile(fset, file); err != nil {
		t.Fatalf("after rename: %v", err)
	}

	pol := ParseDirectives(file)
	obfuscateLiterals(cfg, pkg, fset, file, pol)
	if _, err := formatFile(fset, file); err != nil {
		t.Fatalf("after literals: %v", err)
	}

	obfuscateConstants(cfg, pkg, file, pol)
	if _, err := formatFile(fset, file); err != nil {
		t.Fatalf("after constants: %v", err)
	}

	obfuscateMBA(cfg, pkg, file, pol)
	if _, err := formatFile(fset, file); err != nil {
		t.Fatalf("after mba: %v", err)
	}

	flattenControlFlow(cfg, pkg, file, pol)
	if _, err := formatFile(fset, file); err != nil {
		t.Fatalf("after controlflow: %v", err)
	}
}
