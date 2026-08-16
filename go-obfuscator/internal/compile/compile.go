package compile

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	execproxy "github.com/ai-fuchsia/go-obfuscator/internal/exec"
	"github.com/ai-fuchsia/go-obfuscator/internal/gogarble"
	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
	"github.com/ai-fuchsia/go-obfuscator/internal/mapfile"
)

// Hook intercepts a compile invocation, obfuscates sources, and forwards to the real compiler.
func Hook(toolPath string, args []string) error {
	if handled, err := maybePrintToolVersion(toolPath, args); handled || err != nil {
		if err != nil {
			return err
		}
		os.Exit(0)
	}

	importPath := os.Getenv("TOOLEXEC_IMPORTPATH")
	if importPath == "" {
		importPath = "main"
	}

	cfg := ConfigFromEnv()

	if !shouldObfuscate(importPath, args) {
		return execproxy.Forward(toolPath, args)
	}

	newArgs, err := PrepareCompile(cfg, importPath, args)
	if err != nil {
		return err
	}
	return execproxy.Forward(toolPath, newArgs)
}

// ShouldObfuscate reports whether the package should be transformed.
func ShouldObfuscate(importPath string, compileArgs []string) bool {
	return shouldObfuscate(importPath, compileArgs)
}

// PrepareCompile obfuscates sources and returns the compile arguments to forward.
func PrepareCompile(cfg Config, importPath string, args []string) ([]string, error) {
	if !shouldObfuscate(importPath, args) {
		return args, nil
	}

	paths, flags, err := splitCompileArgs(args)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return args, nil
	}

	absPaths := make([]string, len(paths))
	for i, p := range paths {
		abs, err := resolveSourcePath(importPath, p)
		if err != nil {
			return nil, err
		}
		absPaths[i] = abs
	}

	renamer := newRenamer(cfg, importPath)
	fset := token.NewFileSet()
	obfuscatedPaths := make([]string, 0, len(absPaths))

	for _, path := range absPaths {
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		policies := ParseDirectives(file)
		StripDirectiveComments(file)
		if cfg.StripComments {
			stripComments(file)
		}

		renamer.collectPackageNames(file)
		ast.Walk(renamer, file)
		virtualizeFunctions(cfg, importPath, file, policies)
		obfuscateLiterals(cfg, importPath, fset, file, policies)
		obfuscateConstants(cfg, importPath, file, policies)
		obfuscateMBA(cfg, importPath, file, policies)
		injectJunk(cfg, importPath, file, policies)
		injectOpaquePredicates(cfg, importPath, file, policies)
		flattenControlFlow(cfg, importPath, file, policies)
		injectSecurityGuards(cfg, importPath, file, policies)

		out, err := formatFile(fset, file)
		if err != nil {
			return nil, fmt.Errorf("format %s: %w", path, err)
		}

		if err := debugWrite(cfg, importPath, path, out); err != nil {
			return nil, fmt.Errorf("debug write %s: %w", path, err)
		}

		outPath, err := obfuscatedFilePath(cfg, importPath, path)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(outPath, []byte(out), 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", outPath, err)
		}
		obfuscatedPaths = append(obfuscatedPaths, outPath)
	}

	newFlags := ensureTrimpath(flags, cfg.Tiny)
	return replaceSourcePaths(newFlags, absPaths, obfuscatedPaths), nil
}

func shouldObfuscate(importPath string, compileArgs []string) bool {
	if importPath == "" {
		return false
	}
	patterns := os.Getenv("GOGARBLE")
	if patterns == "" {
		patterns = os.Getenv("GOOVERLAY")
	}
	if patterns == "" {
		return false
	}
	if gogarble.Match(importPath, patterns) {
		return true
	}
	// Built binaries use import path "main" even for module packages.
	if importPath == "main" {
		root := os.Getenv("GOOVERLAY_ROOT")
		if root == "" {
			return false
		}
		for _, arg := range compileArgs {
			if !strings.HasSuffix(arg, ".go") {
				continue
			}
			p := arg
			if abs, err := filepath.Abs(arg); err == nil {
				p = abs
			}
			if strings.HasPrefix(filepath.Clean(p), filepath.Clean(root)) {
				return true
			}
		}
	}
	return false
}

func resolveSourcePath(importPath, path string) (string, error) {
	if root := os.Getenv("GOOVERLAY_ROOT"); root != "" {
		if overlay := os.Getenv("GOOVERLAY"); overlay != "" && strings.HasPrefix(importPath, overlay) {
			rel, _ := strings.CutPrefix(importPath, overlay)
			rel = strings.TrimPrefix(rel, "/")
			candidate := filepath.Join(append([]string{root}, append(strings.Split(rel, "/"), filepath.Base(path))...)...)
			if abs, err := filepath.Abs(candidate); err == nil {
				if _, err := os.Stat(abs); err == nil {
					return abs, nil
				}
			}
		}
	}

	if filepath.IsAbs(path) {
		return path, nil
	}

	if root := os.Getenv("GOOVERLAY_ROOT"); root != "" {
		fromRoot := filepath.Join(root, path)
		if abs, err := filepath.Abs(fromRoot); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs, nil
			}
		}
	}

	if abs, err := filepath.Abs(path); err == nil {
		if _, err := os.Stat(abs); err == nil {
			return abs, nil
		}
	}

	return "", fmt.Errorf("source file not found: %s", path)
}

func sanitize(s string) string {
	return strings.NewReplacer("/", "_", ".", "_", "\\", "_").Replace(s)
}

func maybePrintToolVersion(toolPath string, args []string) (handled bool, err error) {
	if len(args) != 1 || args[0] != "-V=full" {
		return false, nil
	}
	out, err := exec.Command(toolPath, "-V=full").Output()
	if err != nil {
		return true, err
	}
	version := strings.TrimSpace(string(out))
	fmt.Println(version, "gooverlay/0.1.0")
	return true, nil
}

func splitCompileArgs(args []string) (paths []string, flags []string, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if needsValue(arg) && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		if strings.HasSuffix(arg, ".go") {
			paths = append(paths, arg)
			continue
		}
		flags = append(flags, arg)
	}
	return paths, flags, nil
}

func needsValue(flag string) bool {
	if strings.Contains(flag, "=") {
		return false
	}
	switch flag {
	case "-o", "-p", "-lang", "-importcfg", "-embedcfg", "-embedfiles",
		"-trimpath", "-buildid", "-asmhdr", "-symabis", "-linkobj", "-objpath",
		"-goversion", "-c", "-blockprofile", "-cpuprofile", "-memprofile",
		"-traceprofile", "-mutexprofile", "-d":
		return true
	}
	return false
}

func replaceSourcePaths(flags, oldPaths, newPaths []string) []string {
	repl := make(map[string]string, len(oldPaths))
	for i, old := range oldPaths {
		repl[old] = newPaths[i]
	}

	out := make([]string, 0, len(flags)+len(newPaths))
	for _, f := range flags {
		out = append(out, f)
	}
	for _, old := range oldPaths {
		out = append(out, repl[old])
	}
	return out
}

type renamer struct {
	cfg        Config
	pkgPath    string
	names      map[string]string
	scopeStack []map[string]bool
}

func newRenamer(cfg Config, pkgPath string) *renamer {
	return &renamer{
		cfg:     cfg,
		pkgPath: pkgPath,
		names:   make(map[string]string),
	}
}

func (r *renamer) pushScope() {
	r.scopeStack = append(r.scopeStack, make(map[string]bool))
}

func (r *renamer) popScope() {
	r.scopeStack = r.scopeStack[:len(r.scopeStack)-1]
}

func (r *renamer) declare(name string) {
	if len(r.scopeStack) == 0 {
		return
	}
	r.scopeStack[len(r.scopeStack)-1][name] = true
}

func (r *renamer) isDeclared(name string) bool {
	for i := len(r.scopeStack) - 1; i >= 0; i-- {
		if r.scopeStack[i][name] {
			return true
		}
	}
	return false
}

func (r *renamer) mapped(name string) string {
	if !shouldRename(name) {
		return name
	}
	if mapped, ok := r.names[name]; ok {
		return mapped
	}
	mapped := hash.Name(r.cfg.Seed, r.pkgPath, name)
	r.names[name] = mapped
	_ = mapfile.Record(r.cfg.MapFile, r.cfg.Seed, r.pkgPath, "identifier", name, mapped)
	return mapped
}

func shouldRename(name string) bool {
	if name == "" || name == "_" {
		return false
	}
	// Entry points must keep their names for the linker.
	if name == "main" || name == "init" {
		return false
	}
	// Only unexported identifiers.
	first := []rune(name)[0]
	return first >= 'a' && first <= 'z'
}

// RenameFile obfuscates unexported identifiers in a parsed Go file. Exported for tests.
func RenameFile(cfg Config, pkgPath string, file *ast.File, fset *token.FileSet) (string, error) {
	renamer := newRenamer(cfg, pkgPath)
	renamer.collectPackageNames(file)
	ast.Walk(renamer, file)
	return formatFile(fset, file)
}

func formatFile(fset *token.FileSet, file *ast.File) (string, error) {
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, file); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (r *renamer) collectPackageNames(file *ast.File) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name != nil && shouldRename(d.Name.Name) {
				r.mapped(d.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name != nil && shouldRename(s.Name.Name) {
						r.mapped(s.Name.Name)
					}
				case *ast.ValueSpec:
					for _, ident := range s.Names {
						if shouldRename(ident.Name) {
							r.mapped(ident.Name)
						}
					}
				}
			}
		}
	}
}

func (r *renamer) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}

	switch n := node.(type) {
	case *ast.File:
		r.pushScope()
		for _, decl := range n.Decls {
			ast.Walk(r, decl)
		}
		r.popScope()
		return nil

	case *ast.FuncDecl:
		if n.Recv != nil {
			ast.Walk(r, n.Recv)
		}
		if n.Name != nil && shouldRename(n.Name.Name) {
			n.Name.Name = r.mapped(n.Name.Name)
		}
		if n.Type != nil {
			if n.Type.Params != nil {
				r.pushScope()
			}
			ast.Walk(r, n.Type)
		}
		if n.Body != nil {
			ast.Walk(r, n.Body)
		}
		if n.Type != nil && n.Type.Params != nil {
			r.popScope()
		}
		return nil

	case *ast.GenDecl:
		for _, spec := range n.Specs {
			ast.Walk(r, spec)
		}
		return nil

	case *ast.ValueSpec:
		for _, ident := range n.Names {
			if ident.Name == "_" {
				continue
			}
			r.declare(ident.Name)
			ident.Name = r.mapped(ident.Name)
		}
		if n.Type != nil {
			ast.Walk(r, n.Type)
		}
		for _, val := range n.Values {
			ast.Walk(r, val)
		}
		return nil

	case *ast.TypeSpec:
		if n.Name != nil && shouldRename(n.Name.Name) {
			r.declare(n.Name.Name)
			n.Name.Name = r.mapped(n.Name.Name)
		}
		if n.Type != nil {
			ast.Walk(r, n.Type)
		}
		return nil

	case *ast.FieldList:
		for _, field := range n.List {
			r.renameField(field)
		}
		return r

	case *ast.StructType:
		if n.Fields != nil {
			for _, field := range n.Fields.List {
				if field.Names == nil {
					continue
				}
				for _, ident := range field.Names {
					if shouldRename(ident.Name) {
						ident.Name = r.mapped(ident.Name)
					}
				}
			}
		}
		return r

	case *ast.BlockStmt:
		r.pushScope()
		for _, stmt := range n.List {
			ast.Walk(r, stmt)
		}
		r.popScope()
		return nil

	case *ast.RangeStmt:
		r.pushScope()
		if n.Key != nil {
			if ident, ok := n.Key.(*ast.Ident); ok && ident.Name != "_" {
				r.declare(ident.Name)
				ident.Name = r.mapped(ident.Name)
			}
		}
		if n.Value != nil {
			if ident, ok := n.Value.(*ast.Ident); ok && ident.Name != "_" {
				r.declare(ident.Name)
				ident.Name = r.mapped(ident.Name)
			}
		}
		ast.Walk(r, n.X)
		ast.Walk(r, n.Body)
		r.popScope()
		return nil

	case *ast.AssignStmt:
		if n.Tok == token.DEFINE {
			r.pushScope()
			for _, lhs := range n.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
					r.declare(ident.Name)
					ident.Name = r.mapped(ident.Name)
				}
			}
			for _, rhs := range n.Rhs {
				ast.Walk(r, rhs)
			}
			r.popScope()
			return nil
		}
		return r

	case *ast.Ident:
		if n.IsExported() {
			return nil
		}
		if _, known := r.names[n.Name]; known || r.isDeclared(n.Name) {
			n.Name = r.mapped(n.Name)
		}
		return nil
	}

	return r
}

func (r *renamer) renameField(field *ast.Field) {
	if field.Names == nil {
		return
	}
	for _, ident := range field.Names {
		if ident.Name == "_" || !shouldRename(ident.Name) {
			continue
		}
		r.declare(ident.Name)
		ident.Name = r.mapped(ident.Name)
	}
}
