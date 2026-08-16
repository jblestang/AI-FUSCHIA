package compile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestMultipathCreatesVariants(t *testing.T) {
	const src = `package main

import _ "fmt"

//gooverlay:multipath
func score(key string) int {
	n := 0
	for _, r := range key {
		n += int(r)
	}
	return n
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Seed: "mp-test", Multipath: true, PathSeed: "path-test"}
	InjectMultipathInFile(cfg, "example.com/app", file)

	text, err := formatFile(fset, file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "switch") {
		t.Fatalf("expected path dispatcher switch, got:\n%s", text)
	}
	if strings.Count(text, "func ") < 4 {
		t.Fatalf("expected dispatcher + path variants, got:\n%s", text)
	}
}

func TestMultipathPreservesSemantics(t *testing.T) {
	const src = `package main

import _ "fmt"

//gooverlay:multipath
func addBonus(score int) int {
	return score + 42
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Seed: "mp-test", Multipath: true, PathSeed: "fixed-path"}
	InjectMultipathInFile(cfg, "example.com/app", file)

	// Compile-check via format (syntax only); runtime verified in check.sh.
	if _, err := formatFile(fset, file); err != nil {
		t.Fatal(err)
	}
}

func TestMaxDirectiveEnablesMultipath(t *testing.T) {
	const src = `package main

//gooverlay:max
func f() int { return 1 }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pol := ParseDirectives(file)
	cfg := Config{Seed: "max-test"}
	o := pol.ForFunc(file.Decls[0].(*ast.FuncDecl))
	if !PassEnabled(cfg, o, PassMultipath) {
		t.Fatal("max directive should enable multipath")
	}
}
