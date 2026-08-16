package compile

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

const integrityHelperBase = "__gooverlay_ic"

// integrityExpected returns the compile-time checksum for a control-flow transition.
func integrityExpected(caseIdx, nextState int) int64 {
	v := int64(caseIdx)*31 + int64(caseIdx)*17 + int64(nextState)*13
	if v < 0 {
		v = -v
	}
	return v % 997
}

// integrityTransitionGuard wraps a state assignment with an integrity-checked branch.
func integrityTransitionGuard(seed, pkgPath, funcName string, caseIdx int, stateVar string, nextState int, assign *ast.AssignStmt) ast.Stmt {
	expected := integrityExpected(caseIdx, nextState)
	trap := hash.Int(seed, pkgPath, fmt.Sprintf("ic:trap:%s:%d", funcName, caseIdx))%996 + 1
	if trap == nextState || trap == -1 {
		trap = (trap + 1) % 996
	}
	if trap == 0 {
		trap = 1
	}

	icCall := &ast.CallExpr{
		Fun: ast.NewIdent(integrityHelperBase),
		Args: []ast.Expr{
			ast.NewIdent(stateVar),
			intLit(int64(caseIdx)),
			intLit(int64(nextState)),
			intLit(expected),
		},
	}

	return &ast.IfStmt{
		Cond: &ast.BinaryExpr{X: icCall, Op: token.EQL, Y: intLit(int64(nextState))},
		Body: &ast.BlockStmt{List: []ast.Stmt{assign}},
		Else: &ast.BlockStmt{List: []ast.Stmt{&ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent(stateVar)},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{intLit(-1)},
		}}},
	}
}

func injectIntegrityHelper(file *ast.File) ast.Decl {
	if integrityHelperExists(file) {
		return nil
	}
	// func __gooverlay_ic(state, caseIdx, next, expected int) int
	src := fmt.Sprintf(`package p
func %s(state, caseIdx, next, expected int) int {
	actual := int((int64(state)*31 + int64(caseIdx)*17 + int64(next)*13) %% 997)
	if actual == expected {
		return next
	}
	return (next + 1) %% 997
}`, integrityHelperBase)
	return parseHelperFunc(src)
}

func integrityHelperExists(file *ast.File) bool {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name != nil && fn.Name.Name == integrityHelperBase {
			return true
		}
	}
	return false
}
