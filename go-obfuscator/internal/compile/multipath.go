package compile

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"strings"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

const pathIndexHelperBase = "__gooverlay_pathIndex"

func injectMultipath(cfg Config, pkgPath string, file *ast.File, policies *FilePolicies) {
	if policies == nil {
		policies = &FilePolicies{}
	}
	if !anyPassEnabled(cfg, policies, file, PassMultipath) {
		return
	}

	pathCount := multipathCount(cfg)
	if pathCount < 2 {
		return
	}

	pathIndexName := hash.Name(cfg.Seed, pkgPath, pathIndexHelperBase)
	if decls := injectPathIndexHelper(cfg, pkgPath, file, pathIndexName); len(decls) > 0 {
		insertAt := declInsertAfterImports(file)
		for _, d := range decls {
			policies.MarkSkipDecl(d)
		}
		file.Decls = append(file.Decls[:insertAt], append(decls, file.Decls[insertAt:]...)...)
	}

	fset := token.NewFileSet()
	var insert []ast.Decl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name == nil {
			continue
		}
		if fn.Name.Name == "init" || fn.Name.Name == "main" {
			continue
		}
		if fn.Recv != nil {
			continue
		}
		if policies.ShouldSkipDecl(fn) {
			continue
		}
		if !PassEnabled(cfg, policies.ForFunc(fn), PassMultipath) {
			continue
		}
		if !canMultipath(fn) {
			continue
		}

		pathNames := make([]string, pathCount)
		var funcPaths []ast.Decl
		allPaths := true
		for i := 0; i < pathCount; i++ {
			pathName := hash.Name(cfg.Seed, pkgPath, fmt.Sprintf("mp:%s:%d", fn.Name.Name, i))
			pathNames[i] = pathName
			body := cloneBlockStmt(fset, fn.Body)
			if body == nil {
				allPaths = false
				break
			}
			applyPathVariant(cfg, pkgPath, fn, i, body)
			funcPaths = append(funcPaths, &ast.FuncDecl{
				Name: ast.NewIdent(pathName),
				Type: cloneFuncType(fn.Type),
				Body: body,
			})
		}
		if !allPaths {
			continue
		}
		fn.Body = buildPathDispatcher(fn, pathNames, pathIndexName, pathCount)
		insert = append(insert, funcPaths...)
	}

	if len(insert) == 0 {
		return
	}
	insertAt := declInsertAfterImports(file)
	file.Decls = append(file.Decls[:insertAt], append(insert, file.Decls[insertAt:]...)...)
}

func multipathCount(cfg Config) int {
	if cfg.Max {
		return 4
	}
	return 3
}

func canMultipath(fn *ast.FuncDecl) bool {
	if fn.Body == nil || len(fn.Body.List) == 0 {
		return false
	}
	bad := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.GoStmt, *ast.DeferStmt, *ast.SelectStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt:
			bad = true
			return false
		}
		return true
	})
	return !bad
}

func injectPathIndexHelper(cfg Config, pkgPath string, file *ast.File, pathIndexName string) []ast.Decl {
	if pathIndexHelperExists(file, pathIndexName) {
		return nil
	}

	pathSeed := strings.TrimSpace(cfg.PathSeed)
	seedLit := fmt.Sprintf("%q", pathSeed)
	src := fmt.Sprintf(`package p

var __gooverlay_pathCtr int
var __gooverlay_pathSeed = %s

func %s(n int) int {
	if n <= 1 {
		return 0
	}
	__gooverlay_pathCtr++
	h := __gooverlay_pathCtr * 1103515245
	if __gooverlay_pathSeed != "" {
		for i := 0; i < len(__gooverlay_pathSeed); i++ {
			h += int(__gooverlay_pathSeed[i]) << (i %% 8)
		}
	} else {
		h ^= __gooverlay_pathCtr * 7919
	}
	if h < 0 {
		h = -h
	}
	return h %% n
}`, seedLit, pathIndexName)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "path.go", src, 0)
	if err != nil {
		panic(err)
	}
	var decls []ast.Decl
	for _, d := range f.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.IMPORT {
			continue
		}
		decls = append(decls, d)
	}
	return decls
}

func pathIndexHelperExists(file *ast.File, name string) bool {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name != nil && fn.Name.Name == name {
			return true
		}
	}
	return false
}

func buildPathDispatcher(fn *ast.FuncDecl, pathNames []string, pathIndexName string, pathCount int) *ast.BlockStmt {
	cases := make([]ast.Stmt, 0, pathCount+1)
	for i, name := range pathNames {
		cases = append(cases, &ast.CaseClause{
			List: []ast.Expr{intLit(int64(i))},
			Body: []ast.Stmt{pathCallStmt(fn, name)},
		})
	}
	cases = append(cases, &ast.CaseClause{
		Body: []ast.Stmt{pathCallStmt(fn, pathNames[0])},
	})
	switchStmt := &ast.SwitchStmt{
		Tag: &ast.CallExpr{
			Fun:  ast.NewIdent(pathIndexName),
			Args: []ast.Expr{intLit(int64(pathCount))},
		},
		Body: &ast.BlockStmt{List: cases},
	}
	return &ast.BlockStmt{List: []ast.Stmt{switchStmt}}
}

func pathCallStmt(fn *ast.FuncDecl, pathName string) ast.Stmt {
	args := paramIdents(fn.Type)
	call := &ast.CallExpr{Fun: ast.NewIdent(pathName), Args: args}
	if fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
		return &ast.ExprStmt{X: call}
	}
	return &ast.ReturnStmt{Results: []ast.Expr{call}}
}

func paramIdents(ft *ast.FuncType) []ast.Expr {
	if ft == nil || ft.Params == nil {
		return nil
	}
	var args []ast.Expr
	for _, field := range ft.Params.List {
		for _, name := range field.Names {
			args = append(args, ast.NewIdent(name.Name))
		}
	}
	return args
}

func applyPathVariant(cfg Config, pkgPath string, fn *ast.FuncDecl, idx int, body *ast.BlockStmt) {
	switch idx {
	case 0:
		return
	case 1:
		if functionReturnsOnlyInt(fn) {
			wrapReturnsWithIdentity(fn, body)
		}
	case 2:
		wrapBlockWithOpaque(cfg.Seed, pkgPath, fn.Name.Name+":mp2", fn, body)
	default:
		prependPathNoise(cfg.Seed, pkgPath, fn.Name.Name+fmt.Sprintf(":mp%d", idx), body)
	}
}

func functionReturnsOnlyInt(fn *ast.FuncDecl) bool {
	if fn.Type == nil || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	return ok && ident.Name == "int"
}

func prependPathNoise(seed, pkgPath, ctx string, body *ast.BlockStmt) {
	noise := &ast.CallExpr{
		Fun:  ast.NewIdent("len"),
		Args: []ast.Expr{&ast.BasicLit{Kind: token.STRING, Value: `"0"`}},
	}
	stmt := &ast.IfStmt{
		Cond: multiplicationOpaquePredicate(seed, pkgPath, ctx),
		Body: &ast.BlockStmt{List: []ast.Stmt{&ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent("_")},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{noise},
		}}},
	}
	body.List = append([]ast.Stmt{stmt}, body.List...)
}

func wrapReturnsWithIdentity(fn *ast.FuncDecl, body *ast.BlockStmt) {
	resultTypes := resultFieldTypes(fn.Type)
	for i, stmt := range body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			continue
		}
		out := make([]ast.Expr, len(ret.Results))
		for j, r := range ret.Results {
			typ := resultTypes[j]
			out[j] = identityPreserveExpr(r, typ)
		}
		body.List[i] = &ast.ReturnStmt{Results: out}
	}
}

func resultFieldTypes(ft *ast.FuncType) []ast.Expr {
	if ft == nil || ft.Results == nil {
		return nil
	}
	var types []ast.Expr
	for _, field := range ft.Results.List {
		for range field.Names {
			types = append(types, field.Type)
		}
		if len(field.Names) == 0 {
			types = append(types, field.Type)
		}
	}
	return types
}

func identityPreserveExpr(r ast.Expr, typ ast.Expr) ast.Expr {
	if ident, ok := typ.(*ast.Ident); ok {
		switch ident.Name {
		case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr":
			return binOp(paren(r), token.ADD, intLit(0))
		}
	}
	return r
}

func wrapBlockWithOpaque(seed, pkgPath, ctx string, fn *ast.FuncDecl, body *ast.BlockStmt) {
	if len(body.List) == 0 {
		return
	}
	inner := make([]ast.Stmt, len(body.List))
	copy(inner, body.List)
	body.List = []ast.Stmt{&ast.IfStmt{
		Cond: multiplicationOpaquePredicate(seed, pkgPath, ctx),
		Body: &ast.BlockStmt{List: inner},
		Else: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ReturnStmt{Results: zeroValueResults(fn.Type)},
		}},
	}}
}

func zeroValueResults(ft *ast.FuncType) []ast.Expr {
	if ft == nil || ft.Results == nil {
		return nil
	}
	out := make([]ast.Expr, 0, len(ft.Results.List))
	for _, field := range ft.Results.List {
		out = append(out, zeroValue(field.Type))
	}
	return out
}

func cloneFuncType(ft *ast.FuncType) *ast.FuncType {
	if ft == nil {
		return nil
	}
	fset := token.NewFileSet()
	var buf bytes.Buffer
	_ = format.Node(&buf, fset, ft)
	node, err := parser.ParseExpr(string(buf.Bytes()))
	if err != nil {
		return ft
	}
	t, ok := node.(*ast.FuncType)
	if !ok {
		return ft
	}
	return t
}

func cloneBlockStmt(fset *token.FileSet, body *ast.BlockStmt) *ast.BlockStmt {
	if body == nil {
		return nil
	}
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, body); err != nil {
		return nil
	}
	wrapped := "package p\nfunc _() " + string(buf.Bytes())
	f, err := parser.ParseFile(fset, "clone.go", wrapped, 0)
	if err != nil {
		return nil
	}
	fn := f.Decls[0].(*ast.FuncDecl)
	return fn.Body
}

// InjectMultipathInFile applies runtime multi-path dispatch for tests.
func InjectMultipathInFile(cfg Config, pkgPath string, file *ast.File) {
	injectMultipath(cfg, pkgPath, file, ParseDirectives(file))
}
