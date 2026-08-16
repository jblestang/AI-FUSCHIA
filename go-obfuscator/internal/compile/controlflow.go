package compile

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

type controlFlowFlattener struct {
	seed    string
	pkgPath string
}

func flattenControlFlow(cfg Config, pkgPath string, file *ast.File, policies *FilePolicies) {
	if policies == nil {
		policies = &FilePolicies{}
	}
	if !anyPassEnabled(cfg, policies, file, PassControlFlow) {
		return
	}
	if icDecl := injectIntegrityHelper(file); icDecl != nil {
		policies.MarkSkipDecl(icDecl)
		insertAt := declInsertAfterImports(file)
		file.Decls = append(file.Decls[:insertAt], append([]ast.Decl{icDecl}, file.Decls[insertAt:]...)...)
	}
	f := &controlFlowFlattener{seed: cfg.Seed, pkgPath: pkgPath}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Name == nil || fn.Name.Name == "main" || fn.Name.Name == "init" {
			continue
		}
		if fn.Recv != nil {
			continue
		}
		if policies.ShouldSkipDecl(fn) {
			continue
		}
		if !PassEnabled(cfg, policies.ForFunc(fn), PassControlFlow) {
			continue
		}
		if !f.canFlatten(fn.Body) {
			continue
		}
		fn.Body = f.flatten(fn, fn.Body)
	}
}

func (f *controlFlowFlattener) canFlatten(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) < 2 {
		return false
	}
	stmts := body.List
	for _, stmt := range stmts {
		if !f.isFlatStatement(stmt) {
			return false
		}
	}
	// Reordering must not run return before other statements or use-before-def.
	if len(stmts) > 1 {
		for _, stmt := range stmts {
			if _, ok := stmt.(*ast.ReturnStmt); ok {
				return false
			}
		}
	}
	return !hasCrossStatementDeps(stmts)
}

func (f *controlFlowFlattener) isFlatStatement(stmt ast.Stmt) bool {
	switch s := stmt.(type) {
	case *ast.DeclStmt:
		_, ok := s.Decl.(*ast.GenDecl)
		return ok
	case *ast.AssignStmt, *ast.ExprStmt, *ast.IncDecStmt:
		return true
	case *ast.ReturnStmt:
		return true
	default:
		return false
	}
}

// hasCrossStatementDeps reports whether any statement uses a variable defined in an earlier one.
func hasCrossStatementDeps(stmts []ast.Stmt) bool {
	defined := make(map[string]int)
	for i, stmt := range stmts {
		defs := stmtDefs(stmt)
		for name := range defs {
			defined[name] = i
		}
		for name := range stmtUses(stmt, defs) {
			if defIdx, ok := defined[name]; ok && defIdx < i {
				return true
			}
		}
	}
	return false
}

func stmtDefs(stmt ast.Stmt) map[string]struct{} {
	out := make(map[string]struct{})
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		for _, lhs := range s.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
				out[id.Name] = struct{}{}
			}
		}
	case *ast.DeclStmt:
		gen, ok := s.Decl.(*ast.GenDecl)
		if !ok {
			break
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if name.Name != "_" {
					out[name.Name] = struct{}{}
				}
			}
		}
	}
	return out
}

func stmtUses(stmt ast.Stmt, localDefs map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{})
	ast.Inspect(stmt, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || id.Name == "_" || isBuiltinIdent(id.Name) {
			return true
		}
		if _, isDef := localDefs[id.Name]; isDef {
			return true
		}
		out[id.Name] = struct{}{}
		return true
	})
	return out
}

func isBuiltinIdent(name string) bool {
	switch name {
	case "true", "false", "nil", "int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
		"float32", "float64", "complex64", "complex128",
		"byte", "rune", "string", "bool", "error", "any":
		return true
	default:
		return false
	}
}

func (f *controlFlowFlattener) flatten(fn *ast.FuncDecl, body *ast.BlockStmt) *ast.BlockStmt {
	funcName := fn.Name.Name
	stateVar := hash.Name(f.seed, f.pkgPath, "__cf_state_"+funcName)
	hoisted, stmts := f.hoistDeclarations(body.List)
	order := f.stateOrder(funcName, len(stmts))
	cases := make([]ast.Stmt, 0, len(stmts)+1)

	for i, stmtIdx := range order {
		next := -1
		if i+1 < len(order) {
			next = i + 1
		}
		cases = append(cases, f.caseClause(funcName, i, next, stmts[stmtIdx], stateVar))
	}

	switchStmt := &ast.SwitchStmt{
		Tag:  ast.NewIdent(stateVar),
		Body: &ast.BlockStmt{List: cases},
	}

	loop := &ast.ForStmt{
		Body: &ast.BlockStmt{List: []ast.Stmt{
			switchStmt,
			&ast.IfStmt{
				Cond: &ast.BinaryExpr{
					X:  ast.NewIdent(stateVar),
					Op: token.EQL,
					Y:  &ast.BasicLit{Kind: token.INT, Value: "-1"},
				},
				Body: &ast.BlockStmt{List: []ast.Stmt{&ast.BranchStmt{Tok: token.BREAK}}},
			},
		}},
	}

	prelude := []ast.Stmt{
		&ast.DeclStmt{Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{&ast.ValueSpec{
				Names:  []*ast.Ident{ast.NewIdent(stateVar)},
				Values: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: "0"}},
			}},
		}},
	}
	prelude = append(prelude, hoisted...)
	prelude = append(prelude, loop)

	if tail := f.fallbackReturn(fn); tail != nil {
		prelude = append(prelude, tail)
	}

	return &ast.BlockStmt{List: prelude}
}

func (f *controlFlowFlattener) fallbackReturn(fn *ast.FuncDecl) ast.Stmt {
	if fn.Type == nil || fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
		return nil
	}
	results := make([]ast.Expr, 0, len(fn.Type.Results.List))
	for _, field := range fn.Type.Results.List {
		results = append(results, zeroValue(field.Type))
	}
	return &ast.ReturnStmt{Results: results}
}

func zeroValue(typ ast.Expr) ast.Expr {
	switch t := typ.(type) {
	case *ast.Ident:
		switch t.Name {
		case "string":
			return &ast.BasicLit{Kind: token.STRING, Value: `""`}
		case "bool":
			return &ast.Ident{Name: "false"}
		case "error":
			return ast.NewIdent("nil")
		default:
			return &ast.BasicLit{Kind: token.INT, Value: "0"}
		}
	case *ast.StarExpr, *ast.InterfaceType, *ast.MapType, *ast.ChanType, *ast.FuncType:
		return ast.NewIdent("nil")
	default:
		return &ast.BasicLit{Kind: token.INT, Value: "0"}
	}
}

func (f *controlFlowFlattener) hoistDeclarations(stmts []ast.Stmt) (hoisted []ast.Stmt, out []ast.Stmt) {
	var specs []ast.Spec
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.AssignStmt:
			if s.Tok != token.DEFINE {
				out = append(out, s)
				continue
			}
			names := make([]*ast.Ident, 0, len(s.Lhs))
			for _, lhs := range s.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || ident.Name == "_" {
					continue
				}
				names = append(names, ast.NewIdent(ident.Name))
			}
			if len(names) > 0 {
				spec := &ast.ValueSpec{Names: names}
				if len(s.Rhs) == 1 {
					if typ := inferHoistedType(s.Rhs[0]); typ != nil {
						spec.Type = typ
					}
				}
				if spec.Type == nil {
					spec.Type = ast.NewIdent("interface{}")
				}
				specs = append(specs, spec)
				s.Tok = token.ASSIGN
			}
			out = append(out, s)
		default:
			out = append(out, stmt)
		}
	}
	if len(specs) > 0 {
		hoisted = []ast.Stmt{&ast.DeclStmt{Decl: &ast.GenDecl{Tok: token.VAR, Specs: specs}}}
	}
	return hoisted, out
}

func inferHoistedType(expr ast.Expr) ast.Expr {
	switch e := expr.(type) {
	case *ast.BasicLit:
		switch e.Kind {
		case token.INT:
			return ast.NewIdent("int")
		case token.STRING:
			return ast.NewIdent("string")
		case token.FLOAT:
			return ast.NewIdent("float64")
		}
	case *ast.CallExpr:
		return ast.NewIdent("string")
	case *ast.UnaryExpr:
		return inferHoistedType(e.X)
	}
	return nil
}

func (f *controlFlowFlattener) stateOrder(funcName string, n int) []int {
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		hi := hash.Int(f.seed, f.pkgPath, fmt.Sprintf("cf:%s:%d", funcName, order[i]))
		hj := hash.Int(f.seed, f.pkgPath, fmt.Sprintf("cf:%s:%d", funcName, order[j]))
		return hi < hj
	})
	return order
}

func (f *controlFlowFlattener) caseClause(funcName string, caseIdx, next int, stmt ast.Stmt, stateVar string) ast.Stmt {
	body := []ast.Stmt{f.cloneStmt(stmt)}
	if next >= 0 {
		assign := &ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent(stateVar)},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", next)}},
		}
		body = append(body, integrityTransitionGuard(f.seed, f.pkgPath, funcName, caseIdx, stateVar, next, assign))
	} else if _, isReturn := stmt.(*ast.ReturnStmt); !isReturn {
		body = append(body, &ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent(stateVar)},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: "-1"}},
		})
	}

	return &ast.CaseClause{
		List: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", caseIdx)}},
		Body: body,
	}
}

func (f *controlFlowFlattener) cloneStmt(stmt ast.Stmt) ast.Stmt {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		results := make([]ast.Expr, len(s.Results))
		copy(results, s.Results)
		return &ast.ReturnStmt{Results: results}
	case *ast.ExprStmt:
		return &ast.ExprStmt{X: s.X}
	case *ast.IncDecStmt:
		return &ast.IncDecStmt{X: s.X, Tok: s.Tok}
	case *ast.AssignStmt:
		lhs := make([]ast.Expr, len(s.Lhs))
		rhs := make([]ast.Expr, len(s.Rhs))
		copy(lhs, s.Lhs)
		copy(rhs, s.Rhs)
		return &ast.AssignStmt{Lhs: lhs, Tok: s.Tok, Rhs: rhs}
	case *ast.DeclStmt:
		return s
	default:
		return s
	}
}

// FlattenControlFlowInFile applies control-flow flattening for tests.
func FlattenControlFlowInFile(cfg Config, pkgPath string, file *ast.File) {
	flattenControlFlow(cfg, pkgPath, file, ParseDirectives(file))
}
