package compile

import (
	"go/ast"
	"go/token"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

const constantTableBase = "__gooverlay_ctab"

type constantTable struct {
	seed    string
	pkgPath string
	slots   []int64
	sites   map[string]raspFragment
}

func newConstantTable(seed, pkgPath string) *constantTable {
	return &constantTable{
		seed:    seed,
		pkgPath: pkgPath,
		slots:   nil,
		sites:   make(map[string]raspFragment),
	}
}

func (t *constantTable) register(ctx string, value int64) raspFragment {
	if frag, ok := t.sites[ctx]; ok {
		return frag
	}
	// Append dedicated slot pairs so later constants cannot overwrite earlier ones.
	idxA := len(t.slots)
	idxB := len(t.slots) + 1
	t.slots = append(t.slots, 0, 0)
	mask := hash.Int64(t.seed, t.pkgPath, ctx+":mask")
	t.slots[idxA] = mask
	t.slots[idxB] = mask ^ value
	frag := raspFragment{idxA: idxA, idxB: idxB}
	t.sites[ctx] = frag
	return frag
}

func (t *constantTable) readExpr(seed, pkgPath, ctx string, value int64) ast.Expr {
	frag := t.register(ctx, value)
	return &ast.CallExpr{
		Fun:  ast.NewIdent("int"),
		Args: []ast.Expr{raspReadExpr(seed, pkgPath, ctx, frag.idxA, frag.idxB)},
	}
}

func (t *constantTable) injectDecls(file *ast.File, policies *FilePolicies) {
	if len(t.sites) == 0 {
		return
	}
	if tableExists(file, constantTableBase) {
		return
	}

	elts := make([]ast.Expr, len(t.slots))
	for i, v := range t.slots {
		elts[i] = intLit(v)
	}

	tableDecl := &ast.GenDecl{
		Tok: token.VAR,
		Specs: []ast.Spec{&ast.ValueSpec{
			Names: []*ast.Ident{ast.NewIdent(constantTableBase)},
			Values: []ast.Expr{&ast.CompositeLit{
				Type: &ast.ArrayType{Len: nil, Elt: ast.NewIdent("int64")},
				Elts: elts,
			}},
		}},
	}

	insertAt := declInsertAfterImports(file)
	newDecls := []ast.Decl{tableDecl}
	if raspDecls := injectRASPAgent(file, constantTableBase); len(raspDecls) > 0 {
		newDecls = append(newDecls, raspDecls...)
	}
	for _, d := range newDecls {
		if policies != nil {
			policies.MarkSkipDecl(d)
		}
	}
	file.Decls = append(file.Decls[:insertAt], append(newDecls, file.Decls[insertAt:]...)...)
}

func tableExists(file *ast.File, name string) bool {
	for _, decl := range file.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok {
			for _, spec := range gd.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Names) > 0 && vs.Names[0].Name == name {
					return true
				}
			}
		}
	}
	return false
}
