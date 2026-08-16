package compile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func parseFuncBody(t *testing.T, src string) *ast.BlockStmt {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "t.go", "package p\n"+src, 0)
	if err != nil {
		t.Fatal(err)
	}
	fn := file.Decls[0].(*ast.FuncDecl)
	return fn.Body
}

func TestCanFlattenRejectsDependentStatements(t *testing.T) {
	f := &controlFlowFlattener{seed: "test", pkgPath: "p"}
	body := parseFuncBody(t, `func f() {
		title := "SecureLicense Demo"
		_ = title
	}`)
	if f.canFlatten(body) {
		t.Fatal("expected dependent statements to skip flattening")
	}
}

func TestCanFlattenRejectsReturnWithOtherStatements(t *testing.T) {
	f := &controlFlowFlattener{seed: "test", pkgPath: "p"}
	body := parseFuncBody(t, `func f() int {
		_ = 1
		return 2
	}`)
	if f.canFlatten(body) {
		t.Fatal("expected return mixed with other statements to skip flattening")
	}
}

func TestCanFlattenAllowsIndependentStatements(t *testing.T) {
	f := &controlFlowFlattener{seed: "test", pkgPath: "p"}
	body := parseFuncBody(t, `func f() {
		a := 1
		b := 2
	}`)
	if !f.canFlatten(body) {
		t.Fatal("expected independent statements to allow flattening")
	}
}
