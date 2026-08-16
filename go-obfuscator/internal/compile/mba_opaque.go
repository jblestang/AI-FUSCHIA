package compile

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

// multiplicationOpaquePredicate builds (MBA1_A*MBA2_A)==(MBA1_B*MBA2_B) per US12585460 / EP4033381.
func multiplicationOpaquePredicate(seed, pkgPath, ctx string) ast.Expr {
	xVal := int64(hash.Int(seed, pkgPath, ctx+":x"))
	yVal := int64(hash.Int(seed, pkgPath, ctx+":y"))
	x := intLit(xVal)
	y := intLit(yVal)

	// MBA1: x+y == (x^y)+2*(x&y)
	mba1A := binOp(x, token.ADD, y)
	mba1B := binOp(
		paren(binOp(x, token.XOR, y)),
		token.ADD,
		mulInt(paren(binOp(x, token.AND, y)), 2),
	)

	// MBA2: x|y == (x+y)-(x&y)
	mba2A := binOp(x, token.OR, y)
	mba2B := binOp(
		paren(binOp(x, token.ADD, y)),
		token.SUB,
		paren(binOp(x, token.AND, y)),
	)

	left := binOp(paren(mba1A), token.MUL, paren(mba2A))
	right := binOp(paren(mba1B), token.MUL, paren(mba2B))
	return binOp(paren(left), token.EQL, paren(right))
}

func alwaysFalseMBA(seed, pkgPath, ctx string) ast.Expr {
	return &ast.UnaryExpr{Op: token.NOT, X: paren(multiplicationOpaquePredicate(seed, pkgPath, ctx))}
}

// splitBlockWithOpaque inserts an MBA-guarded dead branch between statement groups (EP4033381).
func splitBlockWithOpaque(seed, pkgPath, funcName string, stmts []ast.Stmt) []ast.Stmt {
	if len(stmts) < 3 {
		return stmts
	}
	mid := len(stmts) / 2
	if mid <= 0 || mid >= len(stmts) {
		return stmts
	}
	ctx := fmt.Sprintf("split:%s", funcName)
	out := make([]ast.Stmt, 0, len(stmts)+1)
	out = append(out, stmts[:mid]...)
	out = append(out, &ast.IfStmt{
		Cond: alwaysFalseMBA(seed, pkgPath, ctx),
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ExprStmt{X: &ast.CallExpr{
				Fun:  ast.NewIdent("println"),
				Args: []ast.Expr{intLit(int64(hash.Int(seed, pkgPath, ctx+":dead")))},
			}},
		}},
	})
	out = append(out, stmts[mid:]...)
	return out
}
