package compile

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

type literalObfuscator struct {
	cfg       Config
	policies  *FilePolicies
	seed      string
	pkgPath   string
	index     int
	decryptFn string
	needsHelp bool
	curFn     *ast.FuncDecl
}

func obfuscateLiterals(cfg Config, pkgPath string, fset *token.FileSet, file *ast.File, policies *FilePolicies) {
	if policies == nil {
		policies = &FilePolicies{}
	}
	if !anyPassEnabled(cfg, policies, file, PassLiterals) {
		return
	}
	o := &literalObfuscator{
		cfg:       cfg,
		policies:  policies,
		seed:      cfg.Seed,
		pkgPath:   pkgPath,
		decryptFn: hash.Name(cfg.Seed, pkgPath, "__gooverlay_decrypt"),
	}

	for i, decl := range file.Decls {
		file.Decls[i] = o.transformDecl(decl)
	}
	if o.needsHelp {
		before := len(file.Decls)
		injectDecryptHelper(file, o.decryptFn)
		if policies != nil {
			for _, d := range file.Decls[before:] {
				policies.MarkSkipDecl(d)
			}
		}
	}
}

func injectDecryptHelper(file *ast.File, name string) {
	helper := &ast.FuncDecl{
		Name: ast.NewIdent(name),
		Type: &ast.FuncType{
			Params: &ast.FieldList{List: []*ast.Field{
				{Names: []*ast.Ident{ast.NewIdent("enc")}, Type: &ast.ArrayType{Len: nil, Elt: ast.NewIdent("byte")}},
				{Names: []*ast.Ident{ast.NewIdent("key")}, Type: &ast.ArrayType{Len: nil, Elt: ast.NewIdent("byte")}},
			}},
			Results: &ast.FieldList{List: []*ast.Field{{Type: ast.NewIdent("string")}}},
		},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.DeclStmt{Decl: &ast.GenDecl{
				Tok: token.VAR,
				Specs: []ast.Spec{&ast.ValueSpec{
					Names:  []*ast.Ident{ast.NewIdent("out")},
					Type:   &ast.ArrayType{Len: nil, Elt: ast.NewIdent("byte")},
					Values: []ast.Expr{ast.NewIdent("enc")},
				}},
			}},
			&ast.RangeStmt{
				Key: ast.NewIdent("i"),
				X:   ast.NewIdent("enc"),
				Tok: token.DEFINE,
				Body: &ast.BlockStmt{List: []ast.Stmt{&ast.AssignStmt{
					Lhs: []ast.Expr{&ast.IndexExpr{X: ast.NewIdent("out"), Index: ast.NewIdent("i")}},
					Tok: token.ASSIGN,
					Rhs: []ast.Expr{&ast.BinaryExpr{
						X: &ast.IndexExpr{X: ast.NewIdent("enc"), Index: ast.NewIdent("i")},
						Op: token.XOR,
						Y: &ast.IndexExpr{
							X: ast.NewIdent("key"),
							Index: &ast.BinaryExpr{
								X:  ast.NewIdent("i"),
								Op: token.REM,
								Y:  &ast.CallExpr{Fun: ast.NewIdent("len"), Args: []ast.Expr{ast.NewIdent("key")}},
							},
						},
					}},
				}}},
			},
			&ast.ReturnStmt{Results: []ast.Expr{&ast.CallExpr{
				Fun:  ast.NewIdent("string"),
				Args: []ast.Expr{ast.NewIdent("out")},
			}}},
		}},
	}

	file.Decls = append(file.Decls, helper)
}

func (o *literalObfuscator) transformDecl(decl ast.Decl) ast.Decl {
	if o.policies != nil && o.policies.ShouldSkipDecl(decl) {
		return decl
	}
	switch d := decl.(type) {
	case *ast.FuncDecl:
		prev := o.curFn
		o.curFn = d
		defer func() { o.curFn = prev }()
		if !PassEnabled(o.cfg, o.policies.ForFunc(d), PassLiterals) {
			return d
		}
		if d.Body != nil {
			d.Body = o.transformBlock(d.Body)
		}
		return d
	case *ast.GenDecl:
		if !PassEnabled(o.cfg, o.policies.File, PassLiterals) {
			return d
		}
		if d.Tok == token.CONST && genDeclHasStringLiteral(d) {
			d.Tok = token.VAR
		}
		for i, spec := range d.Specs {
			d.Specs[i] = o.transformSpec(spec)
		}
		return d
	default:
		return decl
	}
}

func genDeclHasStringLiteral(decl *ast.GenDecl) bool {
	for _, spec := range decl.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, v := range vs.Values {
			if lit, ok := v.(*ast.BasicLit); ok && stringLiteralValue(lit) != "" {
				return true
			}
		}
	}
	return false
}

func (o *literalObfuscator) transformSpec(spec ast.Spec) ast.Spec {
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

func (o *literalObfuscator) transformBlock(block *ast.BlockStmt) *ast.BlockStmt {
	for i, stmt := range block.List {
		block.List[i] = o.transformStmt(stmt)
	}
	return block
}

func (o *literalObfuscator) transformStmt(stmt ast.Stmt) ast.Stmt {
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
		s.Body = o.transformBlock(s.Body)
		if s.Else != nil {
			s.Else = o.transformStmt(s.Else)
		}
		return s
	case *ast.ForStmt:
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
		if s.Body != nil {
			s.Body = o.transformBlock(s.Body)
		}
		return s
	case *ast.TypeSwitchStmt:
		if s.Body != nil {
			s.Body = o.transformBlock(s.Body)
		}
		return s
	case *ast.CaseClause:
		for i, stmt := range s.Body {
			s.Body[i] = o.transformStmt(stmt)
		}
		return s
	default:
		return stmt
	}
}

func (o *literalObfuscator) transformExpr(expr ast.Expr) ast.Expr {
	if expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return e
		}
		raw := stringLiteralValue(e)
		if raw == "" {
			return e
		}
		o.needsHelp = true
		return o.encryptedCall(raw)
	case *ast.BinaryExpr:
		e.X = o.transformExpr(e.X)
		e.Y = o.transformExpr(e.Y)
		return e
	case *ast.CallExpr:
		e.Fun = o.transformExpr(e.Fun)
		for i, arg := range e.Args {
			e.Args[i] = o.transformExpr(arg)
		}
		return e
	case *ast.CompositeLit:
		for i, elt := range e.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				kv.Value = o.transformExpr(kv.Value)
				e.Elts[i] = kv
			} else {
				e.Elts[i] = o.transformExpr(elt.(ast.Expr))
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
	case *ast.ParenExpr:
		e.X = o.transformExpr(e.X)
		return e
	case *ast.SelectorExpr:
		e.X = o.transformExpr(e.X)
		return e
	case *ast.StarExpr:
		e.X = o.transformExpr(e.X)
		return e
	case *ast.UnaryExpr:
		e.X = o.transformExpr(e.X)
		return e
	default:
		return expr
	}
}

func stringLiteralValue(lit *ast.BasicLit) string {
	if lit == nil || lit.Kind != token.STRING {
		return ""
	}
	raw, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return raw
}

func (o *literalObfuscator) encryptedCall(raw string) ast.Expr {
	ctx := fmt.Sprintf("literal:%d:%q", o.index, raw)
	o.index++
	keyLen := len(raw)
	if keyLen == 0 {
		keyLen = 1
	}
	key := hash.Bytes(o.seed, o.pkgPath, ctx, keyLen)
	enc := make([]byte, len(raw))
	for i := range raw {
		enc[i] = raw[i] ^ key[i%len(key)]
	}
	return &ast.CallExpr{
		Fun: ast.NewIdent(o.decryptFn),
		Args: []ast.Expr{
			byteSliceLit(enc),
			byteSliceLit(key),
		},
	}
}

func byteSliceLit(data []byte) ast.Expr {
	elts := make([]ast.Expr, len(data))
	for i, b := range data {
		elts[i] = &ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", b)}
	}
	return &ast.CompositeLit{
		Type: &ast.ArrayType{Len: nil, Elt: ast.NewIdent("byte")},
		Elts: elts,
	}
}

// ObfuscateLiteralsInFile applies string literal obfuscation for tests.
func ObfuscateLiteralsInFile(cfg Config, pkgPath string, fset *token.FileSet, file *ast.File) {
	obfuscateLiterals(cfg, pkgPath, fset, file, ParseDirectives(file))
}
