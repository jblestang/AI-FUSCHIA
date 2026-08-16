package compile

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

func injectJunk(cfg Config, pkgPath string, file *ast.File, policies *FilePolicies) {
	if policies == nil {
		policies = &FilePolicies{}
	}
	if !anyPassEnabled(cfg, policies, file, PassJunk) {
		return
	}

	fnName := hash.Name(cfg.Seed, pkgPath, "__gooverlay_junk")
	if junkExists(file, fnName) {
		return
	}

	val := hash.Int(cfg.Seed, pkgPath, "junk:val")
	junk := &ast.FuncDecl{
		Name: ast.NewIdent(fnName),
		Type: &ast.FuncType{Params: &ast.FieldList{}},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.IfStmt{
				Cond: &ast.BinaryExpr{
					X:  intLit(int64(val | 1)),
					Op: token.NEQ,
					Y:  intLit(0),
				},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ExprStmt{X: &ast.CallExpr{
						Fun:  ast.NewIdent("println"),
						Args: []ast.Expr{intLit(int64(val))},
					}},
				}},
				Else: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ExprStmt{X: &ast.CallExpr{
						Fun:  ast.NewIdent("println"),
						Args: []ast.Expr{intLit(int64(val + 1))},
					}},
				}},
			},
		}},
	}
	file.Decls = append(file.Decls, junk)
}

func anyPassEnabled(cfg Config, policies *FilePolicies, file *ast.File, pass PassName) bool {
	if PassEnabled(cfg, policies.File, pass) {
		return true
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if PassEnabled(cfg, policies.ForFunc(fn), pass) {
			return true
		}
	}
	return false
}

func junkExists(file *ast.File, name string) bool {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name != nil && fn.Name.Name == name {
			return true
		}
	}
	return false
}

func injectOpaquePredicates(cfg Config, pkgPath string, file *ast.File, policies *FilePolicies) {
	if policies == nil {
		policies = &FilePolicies{}
	}
	if !anyPassEnabled(cfg, policies, file, PassOpaque) {
		return
	}
	idx := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name == nil {
			continue
		}
		if fn.Name.Name == "init" {
			continue
		}
		if policies.ShouldSkipDecl(fn) {
			continue
		}
		if !PassEnabled(cfg, policies.ForFunc(fn), PassOpaque) {
			continue
		}
		fn.Body = injectDeadBranches(cfg, pkgPath, fn.Name.Name, idx, fn.Body)
		if len(fn.Body.List) >= 3 {
			fn.Body.List = splitBlockWithOpaque(cfg.Seed, pkgPath, fn.Name.Name, fn.Body.List)
		}
		idx++
	}
}

func injectDeadBranches(cfg Config, pkgPath, funcName string, idx int, body *ast.BlockStmt) *ast.BlockStmt {
	if len(body.List) == 0 {
		return body
	}
	ctx := fmt.Sprintf("opaque:%s:%d", funcName, idx)
	val := hash.Int(cfg.Seed, pkgPath, ctx)

	list := make([]ast.Stmt, 0, len(body.List)*2)
	for i, stmt := range body.List {
		if i > 0 && i%2 == 0 {
			if _, prevReturn := body.List[i-1].(*ast.ReturnStmt); !prevReturn {
				list = append(list, deadBranch(cfg, pkgPath, ctx+":dead", val+i))
			}
		}
		list = append(list, stmt)
	}
	return &ast.BlockStmt{List: list}
}

func deadBranch(cfg Config, pkgPath, ctx string, val int) ast.Stmt {
	return &ast.IfStmt{
		Cond: alwaysFalseMBA(cfg.Seed, pkgPath, ctx),
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ExprStmt{X: &ast.CallExpr{
				Fun:  ast.NewIdent("println"),
				Args: []ast.Expr{intLit(int64(val))},
			}},
		}},
	}
}
