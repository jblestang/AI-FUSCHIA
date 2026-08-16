package compile

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

type constantObfuscator struct {
	cfg      Config
	policies *FilePolicies
	seed     string
	pkgPath  string
	index    int
	curFn    *ast.FuncDecl
	table    *constantTable
	file     *ast.File
}

func obfuscateConstants(cfg Config, pkgPath string, file *ast.File, policies *FilePolicies) {
	if policies == nil {
		policies = &FilePolicies{}
	}
	if !anyPassEnabled(cfg, policies, file, PassConstants) {
		return
	}
	o := &constantObfuscator{cfg: cfg, policies: policies, seed: cfg.Seed, pkgPath: pkgPath, file: file, table: newConstantTable(cfg.Seed, pkgPath)}
	for _, decl := range file.Decls {
		o.transformDecl(decl)
	}
	o.table.injectDecls(file, policies)
}

func (o *constantObfuscator) transformDecl(decl ast.Decl) {
	if o.policies != nil && o.policies.ShouldSkipDecl(decl) {
		return
	}
	switch d := decl.(type) {
	case *ast.FuncDecl:
		prev := o.curFn
		o.curFn = d
		defer func() { o.curFn = prev }()
		if !PassEnabled(o.cfg, o.policies.ForFunc(d), PassConstants) {
			return
		}
		if d.Body != nil {
			d.Body = o.transformBlock(d.Body)
		}
	case *ast.GenDecl:
		if d.Tok == token.CONST {
			return
		}
		pol := o.policies.File
		if o.curFn != nil {
			pol = o.policies.ForFunc(o.curFn)
		}
		if !PassEnabled(o.cfg, pol, PassConstants) {
			return
		}
		for i, spec := range d.Specs {
			d.Specs[i] = o.transformSpec(spec)
		}
	}
}

func (o *constantObfuscator) transformSpec(spec ast.Spec) ast.Spec {
	switch s := spec.(type) {
	case *ast.ValueSpec:
		for i, v := range s.Values {
			s.Values[i] = o.transformExpr(v, false)
		}
		return s
	default:
		return spec
	}
}

func (o *constantObfuscator) transformBlock(block *ast.BlockStmt) *ast.BlockStmt {
	for i, stmt := range block.List {
		block.List[i] = o.transformStmt(stmt)
	}
	return block
}

func (o *constantObfuscator) transformStmt(stmt ast.Stmt) ast.Stmt {
	switch s := stmt.(type) {
	case *ast.BlockStmt:
		return o.transformBlock(s)
	case *ast.AssignStmt:
		for i, rhs := range s.Rhs {
			s.Rhs[i] = o.transformExpr(rhs, false)
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
		s.X = o.transformExpr(s.X, false)
		return s
	case *ast.IfStmt:
		s.Cond = o.transformExpr(s.Cond, false)
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
			s.Cond = o.transformExpr(s.Cond, false)
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
			s.Results[i] = o.transformExpr(result, false)
		}
		return s
	case *ast.SwitchStmt:
		if s.Init != nil {
			s.Init = o.transformStmt(s.Init)
		}
		if s.Tag != nil {
			s.Tag = o.transformExpr(s.Tag, false)
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

func (o *constantObfuscator) transformCaseClause(clause *ast.CaseClause) ast.Stmt {
	for i, expr := range clause.List {
		clause.List[i] = o.transformExpr(expr, false)
	}
	for i, stmt := range clause.Body {
		clause.Body[i] = o.transformStmt(stmt)
	}
	return clause
}

func (o *constantObfuscator) transformExpr(expr ast.Expr, inByteSlice bool) ast.Expr {
	if expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.BasicLit:
		if inByteSlice {
			return e
		}
		if isRuneLiteral(e) {
			return o.obfuscateRune(e)
		}
		if v, ok := intValue(e); ok {
			ctx := fmt.Sprintf("const:int:%d:%d", o.index, v)
			o.index++
			return o.obfuscateInt64(ctx, v)
		}
		if v, ok := floatValue(e); ok {
			ctx := fmt.Sprintf("const:float:%d:%v", o.index, v)
			o.index++
			return o.obfuscateFloat64(ctx, v)
		}
		return e
	case *ast.BinaryExpr:
		e.X = o.transformExpr(e.X, inByteSlice)
		e.Y = o.transformExpr(e.Y, inByteSlice)
		return e
	case *ast.UnaryExpr:
		e.X = o.transformExpr(e.X, inByteSlice)
		return e
	case *ast.ParenExpr:
		e.X = o.transformExpr(e.X, inByteSlice)
		return e
	case *ast.CallExpr:
		e.Fun = o.transformExpr(e.Fun, inByteSlice)
		for i, arg := range e.Args {
			e.Args[i] = o.transformExpr(arg, inByteSlice)
		}
		return e
	case *ast.CompositeLit:
		inBytes := inByteSlice || isByteCompositeLit(e)
		for i, elt := range e.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				kv.Value = o.transformExpr(kv.Value, inBytes)
				e.Elts[i] = kv
			} else if ex, ok := elt.(ast.Expr); ok {
				e.Elts[i] = o.transformExpr(ex, inBytes)
			}
		}
		return e
	case *ast.IndexExpr:
		e.X = o.transformExpr(e.X, inByteSlice)
		e.Index = o.transformExpr(e.Index, inByteSlice)
		return e
	case *ast.SliceExpr:
		e.X = o.transformExpr(e.X, inByteSlice)
		if e.Low != nil {
			e.Low = o.transformExpr(e.Low, inByteSlice)
		}
		if e.High != nil {
			e.High = o.transformExpr(e.High, inByteSlice)
		}
		if e.Max != nil {
			e.Max = o.transformExpr(e.Max, inByteSlice)
		}
		return e
	case *ast.SelectorExpr:
		e.X = o.transformExpr(e.X, inByteSlice)
		return e
	case *ast.StarExpr:
		e.X = o.transformExpr(e.X, inByteSlice)
		return e
	default:
		return expr
	}
}

func (o *constantObfuscator) obfuscateRune(lit *ast.BasicLit) ast.Expr {
	r, err := strconvQuoteRune(lit.Value)
	if err != nil {
		return lit
	}
	ctx := fmt.Sprintf("const:rune:%d:%d", o.index, r)
	o.index++
	return o.obfuscateInt64(ctx, r)
}

func (o *constantObfuscator) obfuscateInt64(ctx string, value int64) ast.Expr {
	if o.table == nil {
		o.table = newConstantTable(o.seed, o.pkgPath)
	}
	return o.table.readExpr(o.seed, o.pkgPath, ctx, value)
}

func (o *constantObfuscator) obfuscateFloat64(ctx string, value float64) ast.Expr {
	a := float64(hash.Uint64(o.seed, o.pkgPath, ctx+":a")%10000) / 100.0
	b := a - value
	return binOp(floatLit(a), token.SUB, floatLit(b))
}

func strconvQuoteRune(src string) (int64, error) {
	r, err := strconv.Unquote(src)
	if err != nil {
		return 0, err
	}
	if r == "" {
		return 0, fmt.Errorf("empty rune literal")
	}
	return int64([]rune(r)[0]), nil
}

// ObfuscateConstantsInFile applies constant obfuscation for tests.
func ObfuscateConstantsInFile(cfg Config, pkgPath string, file *ast.File) {
	obfuscateConstants(cfg, pkgPath, file, ParseDirectives(file))
}
