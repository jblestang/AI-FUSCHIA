package compile

import (
	"go/ast"
	"go/token"
)

type mbaObfuscator struct {
	cfg      Config
	policies *FilePolicies
	seed     string
	pkgPath  string
	curFn    *ast.FuncDecl
}

func obfuscateMBA(cfg Config, pkgPath string, file *ast.File, policies *FilePolicies) {
	if policies == nil {
		policies = &FilePolicies{}
	}
	if !anyPassEnabled(cfg, policies, file, PassMBA) {
		return
	}
	o := &mbaObfuscator{cfg: cfg, policies: policies, seed: cfg.Seed, pkgPath: pkgPath}
	for _, decl := range file.Decls {
		o.transformDecl(decl)
	}
}

func (o *mbaObfuscator) transformDecl(decl ast.Decl) {
	if o.policies != nil && o.policies.ShouldSkipDecl(decl) {
		return
	}
	switch d := decl.(type) {
	case *ast.FuncDecl:
		prev := o.curFn
		o.curFn = d
		defer func() { o.curFn = prev }()
		if !PassEnabled(o.cfg, o.policies.ForFunc(d), PassMBA) {
			return
		}
		if d.Body != nil {
			d.Body = o.transformBlock(d.Body)
		}
	case *ast.GenDecl:
		pol := o.policies.File
		if o.curFn != nil {
			pol = o.policies.ForFunc(o.curFn)
		}
		if !PassEnabled(o.cfg, pol, PassMBA) {
			return
		}
		for i, spec := range d.Specs {
			d.Specs[i] = o.transformSpec(spec)
		}
	}
}

func (o *mbaObfuscator) transformSpec(spec ast.Spec) ast.Spec {
	switch s := spec.(type) {
	case *ast.ValueSpec:
		for i, v := range s.Values {
			s.Values[i] = o.transformExpr(v)
		}
		return s
	default:
		return spec
	}
}

func (o *mbaObfuscator) transformBlock(block *ast.BlockStmt) *ast.BlockStmt {
	for i, stmt := range block.List {
		block.List[i] = o.transformStmt(stmt)
	}
	return block
}

func (o *mbaObfuscator) transformStmt(stmt ast.Stmt) ast.Stmt {
	switch s := stmt.(type) {
	case *ast.BlockStmt:
		return o.transformBlock(s)
	case *ast.AssignStmt:
		for i, rhs := range s.Rhs {
			s.Rhs[i] = o.transformExpr(rhs)
		}
		return s
	case *ast.DeclStmt:
		if decl, ok := s.Decl.(*ast.GenDecl); ok {
			for i, spec := range decl.Specs {
				decl.Specs[i] = o.transformSpec(spec)
			}
		}
		return s
	case *ast.ExprStmt:
		s.X = o.transformExpr(s.X)
		return s
	case *ast.IfStmt:
		s.Cond = o.transformExpr(s.Cond)
		s.Body = o.transformBlock(s.Body)
		if s.Else != nil {
			s.Else = o.transformStmt(s.Else)
		}
		return s
	case *ast.ForStmt:
		if s.Init != nil {
			s.Init = o.transformStmt(s.Init)
		}
		if s.Cond != nil {
			s.Cond = o.transformExpr(s.Cond)
		}
		if s.Post != nil {
			s.Post = o.transformStmt(s.Post)
		}
		if s.Body != nil {
			s.Body = o.transformBlock(s.Body)
		}
		return s
	case *ast.RangeStmt:
		if s.Body != nil {
			s.Body = o.transformBlock(s.Body)
		}
		return s
	case *ast.ReturnStmt:
		for i, result := range s.Results {
			s.Results[i] = o.transformExpr(result)
		}
		return s
	case *ast.SwitchStmt:
		if s.Init != nil {
			s.Init = o.transformStmt(s.Init)
		}
		if s.Tag != nil {
			s.Tag = o.transformExpr(s.Tag)
		}
		if s.Body != nil {
			for i, stmt := range s.Body.List {
				if clause, ok := stmt.(*ast.CaseClause); ok {
					s.Body.List[i] = o.transformCaseClause(clause)
				}
			}
		}
		return s
	default:
		return stmt
	}
}

func (o *mbaObfuscator) transformCaseClause(clause *ast.CaseClause) ast.Stmt {
	for i, expr := range clause.List {
		clause.List[i] = o.transformExpr(expr)
	}
	for i, stmt := range clause.Body {
		clause.Body[i] = o.transformStmt(stmt)
	}
	return clause
}

func (o *mbaObfuscator) transformExpr(expr ast.Expr) ast.Expr {
	if expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		e.X = o.transformExpr(e.X)
		e.Y = o.transformExpr(e.Y)
		return o.rewriteBinary(e)
	case *ast.UnaryExpr:
		e.X = o.transformExpr(e.X)
		return e
	case *ast.ParenExpr:
		e.X = o.transformExpr(e.X)
		return e
	case *ast.CallExpr:
		e.Fun = o.transformExpr(e.Fun)
		for i, arg := range e.Args {
			e.Args[i] = o.transformExpr(arg)
		}
		return e
	case *ast.CompositeLit:
		if isByteCompositeLit(e) {
			return e
		}
		for i, elt := range e.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				kv.Value = o.transformExpr(kv.Value)
				e.Elts[i] = kv
			} else if ex, ok := elt.(ast.Expr); ok {
				e.Elts[i] = o.transformExpr(ex)
			}
		}
		return e
	case *ast.IndexExpr:
		e.X = o.transformExpr(e.X)
		e.Index = o.transformExpr(e.Index)
		return e
	case *ast.SliceExpr:
		e.X = o.transformExpr(e.X)
		if e.Low != nil {
			e.Low = o.transformExpr(e.Low)
		}
		if e.High != nil {
			e.High = o.transformExpr(e.High)
		}
		if e.Max != nil {
			e.Max = o.transformExpr(e.Max)
		}
		return e
	case *ast.SelectorExpr:
		e.X = o.transformExpr(e.X)
		return e
	case *ast.StarExpr:
		e.X = o.transformExpr(e.X)
		return e
	default:
		return expr
	}
}

func (o *mbaObfuscator) rewriteBinary(e *ast.BinaryExpr) ast.Expr {
	switch e.Op {
	case token.ADD, token.SUB, token.XOR, token.OR, token.AND:
	default:
		return e
	}

	x := paren(e.X)
	y := paren(e.Y)

	switch e.Op {
	case token.ADD:
		// x + y == (x ^ y) + 2*(x & y)
		return binOp(
			paren(binOp(x, token.XOR, y)),
			token.ADD,
			mulInt(paren(binOp(x, token.AND, y)), 2),
		)
	case token.SUB:
		// x - y == (x ^ y) - 2*(^x & y)
		return binOp(
			paren(binOp(x, token.XOR, y)),
			token.SUB,
			mulInt(paren(binOp(paren(&ast.UnaryExpr{Op: token.XOR, X: x}), token.AND, y)), 2),
		)
	case token.XOR:
		// x ^ y == (x | y) - (x & y)
		return binOp(
			paren(binOp(x, token.OR, y)),
			token.SUB,
			paren(binOp(x, token.AND, y)),
		)
	case token.OR:
		// x | y == (x ^ y) + (x & y)
		return binOp(
			paren(binOp(x, token.XOR, y)),
			token.ADD,
			paren(binOp(x, token.AND, y)),
		)
	case token.AND:
		// x & y == (x | y) ^ (x ^ y)
		return binOp(
			paren(binOp(x, token.OR, y)),
			token.XOR,
			paren(binOp(x, token.XOR, y)),
		)
	default:
		return e
	}
}

// ObfuscateMBAInFile applies MBA obfuscation for tests.
func ObfuscateMBAInFile(cfg Config, pkgPath string, file *ast.File) {
	obfuscateMBA(cfg, pkgPath, file, ParseDirectives(file))
}
