package compile

import "go/ast"

// InjectOpaqueInFile applies opaque predicate injection for tests.
func InjectOpaqueInFile(cfg Config, pkgPath string, file *ast.File) {
	injectOpaquePredicates(cfg, pkgPath, file, ParseDirectives(file))
}
