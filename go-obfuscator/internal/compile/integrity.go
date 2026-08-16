package compile

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

const integrityHelperBase = "__gooverlay_ic"

// integrityExpected returns the compile-time expected checksum for a control-flow case (US11250110).
func integrityExpected(seed, pkgPath, funcName string, caseIdx, state int) int64 {
	h := hash.Int64(seed, pkgPath, fmt.Sprintf("ic:%s:%d:%d", funcName, caseIdx, state))
	if h < 0 {
		h = -h
	}
	return h
}

// integrityTransitionGuard wraps a state assignment with an integrity-checked branch.
func integrityTransitionGuard(seed, pkgPath, funcName string, caseIdx int, stateVar string, nextState int, assign *ast.AssignStmt) ast.Stmt {
	expected := integrityExpected(seed, pkgPath, funcName, caseIdx, nextState)
	trap := hash.Int(seed, pkgPath, fmt.Sprintf("ic:trap:%s:%d", funcName, caseIdx)) % 997
	if trap == nextState {
		trap = (trap + 1) % 997
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
			Rhs: []ast.Expr{intLit(int64(trap))},
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
	v := int64(state)*31 + int64(caseIdx)*17 + int64(next)*13
	v ^= int64(expected)
	if v < 0 { v = -v }
	mod := int(v %% 997)
	if next < 0 {
		if mod == 996 { return -1 }
		return -2
	}
	target := next %% 997
	if target < 0 { target += 997 }
	if mod == target { return next }
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
