package compile

import (
	"go/ast"
	"go/token"
	"strconv"
)

func intLit(v int64) *ast.BasicLit {
	return &ast.BasicLit{Kind: token.INT, Value: strconv.FormatInt(v, 10)}
}

func floatLit(v float64) *ast.BasicLit {
	return &ast.BasicLit{Kind: token.FLOAT, Value: strconv.FormatFloat(v, 'f', -1, 64)}
}

func paren(expr ast.Expr) ast.Expr {
	return &ast.ParenExpr{X: expr}
}

func binOp(x ast.Expr, op token.Token, y ast.Expr) ast.Expr {
	return &ast.BinaryExpr{X: x, Op: op, Y: y}
}

func mulInt(expr ast.Expr, n int64) ast.Expr {
	if n == 1 {
		return expr
	}
	return binOp(intLit(n), token.MUL, paren(expr))
}

func intValue(lit *ast.BasicLit) (int64, bool) {
	if lit == nil || lit.Kind != token.INT {
		return 0, false
	}
	if len(lit.Value) > 0 && (lit.Value[0] == '\'' || lit.Value[0] == '"') {
		return 0, false
	}
	v, err := strconv.ParseInt(lit.Value, 0, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func floatValue(lit *ast.BasicLit) (float64, bool) {
	if lit == nil || lit.Kind != token.FLOAT {
		return 0, false
	}
	v, err := strconv.ParseFloat(lit.Value, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func isRuneLiteral(lit *ast.BasicLit) bool {
	return lit != nil && lit.Kind == token.INT && len(lit.Value) > 0 && lit.Value[0] == '\''
}

func isByteCompositeLit(expr ast.Expr) bool {
	cl, ok := expr.(*ast.CompositeLit)
	if !ok || cl.Type == nil {
		return false
	}
	arr, ok := cl.Type.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	ident, ok := arr.Elt.(*ast.Ident)
	return ok && ident.Name == "byte"
}
