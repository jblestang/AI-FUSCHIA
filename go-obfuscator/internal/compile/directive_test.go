package compile_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/ai-fuchsia/go-obfuscator/internal/compile"
)

func TestParseDirectivesOnFunction(t *testing.T) {
	const src = `package main

//gooverlay:virtualize no-mba
func apply(n int) int {
	return n + 1
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pol := compile.ParseDirectives(file)
	fn := file.Decls[0].(*ast.FuncDecl)
	o := pol.ForFunc(fn)

	cfg := compile.Config{Virtualize: false, MBA: true}
	if !compile.PassEnabled(cfg, o, compile.PassVirtualize) {
		t.Fatal("expected virtualize enabled by annotation")
	}
	if compile.PassEnabled(cfg, o, compile.PassMBA) {
		t.Fatal("expected mba disabled by annotation")
	}
}

func TestParseDirectivesSkipAll(t *testing.T) {
	const src = `package main

//gooverlay:off
func secret() {}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pol := compile.ParseDirectives(file)
	fn := file.Decls[0].(*ast.FuncDecl)
	cfg := compile.Config{Literals: true, MBA: true}
	if compile.PassEnabled(cfg, pol.ForFunc(fn), compile.PassLiterals) {
		t.Fatal("expected skip all")
	}
}

func TestFileLevelDirective(t *testing.T) {
	const src = `//gooverlay:file literals
package main

func f() {}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pol := compile.ParseDirectives(file)
	fn := file.Decls[0].(*ast.FuncDecl)
	cfg := compile.Config{Literals: false}
	if !compile.PassEnabled(cfg, pol.ForFunc(fn), compile.PassLiterals) {
		t.Fatal("expected file-level literals enable")
	}
}
