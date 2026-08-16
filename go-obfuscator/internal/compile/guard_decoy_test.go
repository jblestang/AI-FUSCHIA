package compile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestGuardDecoysInjectedButUncalled(t *testing.T) {
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
	cfg := Config{Seed: "decoy-test", Tamper: true, AntiDebug: true, AntiEmulation: true}
	injectSecurityGuards(cfg, "example.com/app", file, ParseDirectives(file))

	decoys := makeDecoyFuncNames(cfg, "example.com/app", "")
	text := formatFileMust(t, fset, file)

	for _, name := range []string{decoys.integrity, decoys.antiDebug, decoys.antiEmu, decoys.report, decoys.securityOK} {
		if !strings.Contains(text, "func "+name) {
			t.Fatalf("missing decoy guard func %q in:\n%s", name, text)
		}
	}
	for _, forbidden := range []string{"__gooverlay_integrity", "__gooverlay_report_tamper"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("decoy bait string %q must be XOR-encoded, not cleartext", forbidden)
		}
	}

	calls := decoyCallSites(file, decoys)
	if len(calls) > 0 {
		t.Fatalf("decoy guards must not be called from application code, found calls to: %v", calls)
	}
}

func formatFileMust(t *testing.T, fset *token.FileSet, file *ast.File) string {
	t.Helper()
	out, err := formatFile(fset, file)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func decoyCallSites(file *ast.File, decoys decoyGuardNames) []string {
	targets := map[string]string{
		decoys.integrity:  "integrity",
		decoys.antiDebug:  "antidebug",
		decoys.antiEmu:    "antiemu",
		decoys.report:     "report",
		decoys.securityOK: "secok",
	}
	var hits []string
	appFuncs := map[string]bool{"main": true, "work": true}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name == nil || !appFuncs[fn.Name.Name] {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if label, ok := targets[id.Name]; ok {
				hits = append(hits, label)
			}
			return true
		})
	}
	return hits
}
