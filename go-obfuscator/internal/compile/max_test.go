package compile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestMaxDirectiveEnablesAllPasses(t *testing.T) {
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
	for _, pass := range []PassName{
		PassLiterals, PassConstants, PassMBA, PassControlFlow, PassVirtualize,
		PassJunk, PassOpaque, PassTamper, PassAntiDebug, PassAntiEmulation,
	} {
		if !PassEnabled(cfg, o, pass) {
			t.Fatalf("max directive should enable pass %q", pass)
		}
	}
}

func TestApplyMaxDefaults(t *testing.T) {
	cfg := Config{Seed: "x"}
	ApplyMaxDefaults(&cfg)
	if !cfg.Max || !cfg.Literals || !cfg.Virtualize || !cfg.ControlFlow || !cfg.Tamper {
		t.Fatalf("ApplyMaxDefaults should enable all passes: %+v", cfg)
	}
}
