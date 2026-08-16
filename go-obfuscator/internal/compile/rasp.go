package compile

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
)

type raspFragment struct {
	idxA int
	idxB int
}

func injectRASPAgent(file *ast.File, tableName, agentName, okVarName string) []ast.Decl {
	if raspAgentExists(file, agentName) {
		return nil
	}
	src := fmt.Sprintf(`package p
var %s = true

func %s(a, b, tag int) int64 {
	if !%s {
		return int64(tag) ^ 0xdeadbeef
	}
	return %s[a] ^ %s[b]
}`, okVarName, agentName, okVarName, tableName, tableName)
	return parseHelperDecls(src)
}

func raspAgentExists(file *ast.File, agentName string) bool {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name != nil && fn.Name.Name == agentName {
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
