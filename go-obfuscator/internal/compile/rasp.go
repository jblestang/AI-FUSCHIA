package compile

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

const raspAgentBase = "__gooverlay_rasp"

type raspFragment struct {
	idxA int
	idxB int
}

// raspReadExpr returns agent call reconstructing value from two table slots (US12045338 lite).
func raspReadExpr(seed, pkgPath, ctx string, idxA, idxB int) ast.Expr {
	tag := hash.Int(seed, pkgPath, ctx+":tag")
	return &ast.CallExpr{
		Fun: ast.NewIdent(raspAgentBase),
		Args: []ast.Expr{
			intLit(int64(idxA)),
			intLit(int64(idxB)),
			intLit(int64(tag)),
		},
	}
}

func injectRASPAgent(file *ast.File, tableName string) []ast.Decl {
	if raspAgentExists(file) {
		return nil
	}
	src := fmt.Sprintf(`package p
var __gooverlay_rasp_ok = true

func %s(a, b, tag int) int64 {
	if !__gooverlay_rasp_ok {
		return int64(tag) ^ 0xdeadbeef
	}
	return %s[a] ^ %s[b]
}`, raspAgentBase, tableName, tableName)
	return parseHelperDecls(src)
}

func raspAgentExists(file *ast.File) bool {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name != nil && fn.Name.Name == raspAgentBase {
			return true
		}
	}
	return false
}

func parseHelperDecls(src string) []ast.Decl {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "helper.go", src, 0)
	if err != nil {
		panic(err)
	}
	return f.Decls
}

func parseHelperFunc(src string) ast.Decl {
	decls := parseHelperDecls(src)
	if len(decls) == 0 {
		panic("empty helper source")
	}
	return decls[len(decls)-1]
}
