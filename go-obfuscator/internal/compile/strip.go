package compile

import "go/ast"

func stripComments(file *ast.File) {
	file.Comments = nil
	file.Doc = nil
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			d.Doc = nil
		case *ast.GenDecl:
			d.Doc = nil
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					s.Doc = nil
				case *ast.ValueSpec:
					s.Doc = nil
				case *ast.ImportSpec:
					s.Doc = nil
				}
			}
		}
	}
}
