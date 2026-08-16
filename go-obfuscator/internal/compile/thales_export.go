package compile

import "go/ast"

// InjectSecurityGuardsInFile applies tamper and anti-debug injection for tests.
func InjectSecurityGuardsInFile(cfg Config, pkgPath string, file *ast.File) {
	injectSecurityGuards(cfg, pkgPath, file, ParseDirectives(file))
}
