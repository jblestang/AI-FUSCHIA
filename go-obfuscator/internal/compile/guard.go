package compile

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

func injectSecurityGuards(cfg Config, pkgPath string, file *ast.File, policies *FilePolicies) {
	if policies == nil {
		policies = &FilePolicies{}
	}
	tamperOn := anyPassEnabled(cfg, policies, file, PassTamper)
	antiDebugOn := anyPassEnabled(cfg, policies, file, PassAntiDebug)
	antiEmulationOn := anyPassEnabled(cfg, policies, file, PassAntiEmulation)
	if !tamperOn && !antiDebugOn && !antiEmulationOn {
		return
	}

	syms := guardSymbolsFor(cfg, pkgPath)
	guardKey := hash.Int64(cfg.Seed, pkgPath, "guard:key")
	if decls := injectGuardRuntime(cfg, pkgPath, file, syms, guardKey); len(decls) > 0 {
		insertAt := declInsertAfterImports(file)
		for _, d := range decls {
			policies.MarkSkipDecl(d)
		}
		file.Decls = append(file.Decls[:insertAt], append(decls, file.Decls[insertAt:]...)...)
	}
	if decoys := injectGuardDecoys(cfg, pkgPath, file, syms); len(decoys) > 0 {
		insertAt := declInsertAfterImports(file)
		for _, d := range decoys {
			policies.MarkSkipDecl(d)
		}
		file.Decls = append(file.Decls[:insertAt], append(decoys, file.Decls[insertAt:]...)...)
	}

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
		pol := policies.ForFunc(fn)
		if pol.SkipAll {
			continue
		}

		prefix := make([]ast.Stmt, 0, 3)
		if tamperOn && PassEnabled(cfg, pol, PassTamper) {
			prefix = append(prefix, tamperCheckStmt(cfg, pkgPath, fn.Name.Name, guardKey, syms))
		}
		if antiDebugOn && PassEnabled(cfg, pol, PassAntiDebug) {
			prefix = append(prefix, antiDebugCheckStmt(syms, 98))
		}
		if antiEmulationOn && PassEnabled(cfg, pol, PassAntiEmulation) {
			prefix = append(prefix, antiEmulationCheckStmt(syms, 97))
		}
		if len(prefix) == 0 {
			continue
		}
		fn.Body.List = append(prefix, fn.Body.List...)
	}
}

func tamperCheckStmt(cfg Config, pkgPath, funcName string, guardKey int64, syms guardSymbols) ast.Stmt {
	tag := hash.Int(cfg.Seed, pkgPath, "guard:tag:"+funcName) % 1000000
	expected := int((int64(tag)*31 + guardKey) % 997)
	exitCode := hash.Int(cfg.Seed, pkgPath, "guard:exit:"+funcName)%89 + 10

	return &ast.IfStmt{
		Cond: &ast.UnaryExpr{
			Op: token.NOT,
			X: &ast.CallExpr{
				Fun: ast.NewIdent(syms.integrity),
				Args: []ast.Expr{
					intLit(int64(tag)),
					intLit(int64(expected)),
				},
			},
		},
		Body: &ast.BlockStmt{List: guardFailStmts(syms, exitCode)},
	}
}

func antiDebugCheckStmt(syms guardSymbols, code int) ast.Stmt {
	return &ast.IfStmt{
		Cond: &ast.CallExpr{Fun: ast.NewIdent(syms.antiDebug)},
		Body: &ast.BlockStmt{List: guardFailStmts(syms, code)},
	}
}

func antiEmulationCheckStmt(syms guardSymbols, code int) ast.Stmt {
	return &ast.IfStmt{
		Cond: &ast.CallExpr{Fun: ast.NewIdent(syms.antiEmulation)},
		Body: &ast.BlockStmt{List: guardFailStmts(syms, code)},
	}
}

func guardFailStmts(syms guardSymbols, code int) []ast.Stmt {
	return []ast.Stmt{
		&ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent(syms.tampered)},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{&ast.Ident{Name: "true"}},
		},
		&ast.ExprStmt{X: &ast.CallExpr{
			Fun: &ast.SelectorExpr{
				X:   ast.NewIdent("os"),
				Sel: ast.NewIdent("Exit"),
			},
			Args: []ast.Expr{intLit(int64(code))},
		}},
	}
}

type guardStringEntry struct {
	ctx   string
	plain string
}

func injectGuardRuntime(cfg Config, pkgPath string, file *ast.File, syms guardSymbols, guardKey int64) []ast.Decl {
	if guardRuntimeExists(file, syms.integrity) {
		return nil
	}

	stringsToHide := []guardStringEntry{
		{ctx: "goos", plain: "linux"},
		{ctx: "proc-status", plain: "/proc/self/status"},
		{ctx: "tracer", plain: "TracerPid:"},
		{ctx: "nl", plain: "\n"},
		{ctx: "proc-cpu", plain: "/proc/cpuinfo"},
		{ctx: "needle-qemu", plain: "qemu virtual"},
		{ctx: "needle-kvm", plain: "common kvm processor"},
		{ctx: "needle-vcpu", plain: "virtual cpu"},
		{ctx: "needle-uemu", plain: "user-mode emulation"},
		{ctx: "needle-bochs", plain: "bochs"},
		{ctx: "needle-vbox", plain: "vbox"},
		{ctx: "needle-vmware", plain: "vmware virtual platform"},
		{ctx: "needle-tcg", plain: "tcg guest"},
		{ctx: "dmi-product", plain: "/sys/class/dmi/id/product_name"},
		{ctx: "dmi-vendor", plain: "/sys/class/dmi/id/sys_vendor"},
		{ctx: "dmi-board", plain: "/sys/class/dmi/id/board_vendor"},
		{ctx: "dmi-qemu", plain: "qemu"},
		{ctx: "dmi-bochs", plain: "bochs"},
		{ctx: "dmi-vbox", plain: "virtualbox"},
		{ctx: "dmi-vbox2", plain: "vbox"},
		{ctx: "dmi-vmware", plain: "vmware"},
		{ctx: "dmi-indie", plain: "independent virtual"},
		{ctx: "dev-qemu", plain: "/dev/qemu_pipe"},
		{ctx: "dev-gold", plain: "/dev/goldfish_pipe"},
		{ctx: "dev-wsock", plain: "/dev/wsocket"},
		{ctx: "dev-fw", plain: "/sys/firmware/qemu_fw_cfg"},
		{ctx: "env-qemu", plain: "QEMU_ENV"},
		{ctx: "env-under", plain: "UNDER_QEMU"},
		{ctx: "env-unicorn", plain: "UNICORN_ENGINE"},
	}

	var varDecls strings.Builder
	decodeCalls := make(map[string]string)
	for _, entry := range stringsToHide {
		key := hash.Bytes(cfg.Seed, pkgPath, "guard:skey:"+entry.ctx, 8)
		enc := xorEncode(entry.plain, key)
		encVar := hash.Name(cfg.Seed, pkgPath, "guard:enc:"+entry.ctx)
		keyVar := hash.Name(cfg.Seed, pkgPath, "guard:k:"+entry.ctx)
		fmt.Fprintf(&varDecls, "\t%s = %s\n\t%s = %s\n", encVar, formatByteSlice(enc), keyVar, formatByteSlice(key))
		decodeCalls[entry.ctx] = fmt.Sprintf("%s(%s, %s)", syms.decrypt, encVar, keyVar)
	}

	src := fmt.Sprintf(`package p

import (
	"os"
	"runtime"
	"strings"
)

var %s bool
var %s int64 = %d

var (
%s)

func %s(enc, key []byte) string {
	out := make([]byte, len(enc))
	for i := range enc {
		out[i] = enc[i] ^ key[i%%len(key)]
	}
	return string(out)
}

func %s(tag, expected int) bool {
	if %s {
		return false
	}
	actual := int((int64(tag)*31 + %s) %% 997)
	ok := actual == expected
	if !ok {
		%s = true
	}
	return ok
}

func %s() bool {
	if runtime.GOOS != %s {
		return false
	}
	data, err := os.ReadFile(%s)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), %s) {
		if strings.HasPrefix(line, %s) {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return true
			}
		}
	}
	return false
}

func %s() bool {
	ppid := os.Getppid()
	return ppid > 1 && ppid != os.Getpid()
}

func %s() bool {
	if runtime.GOOS != %s {
		return false
	}
	data, err := os.ReadFile(%s)
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	for _, needle := range []string{%s, %s, %s, %s, %s, %s, %s, %s} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func %s() bool {
	if runtime.GOOS != %s {
		return false
	}
	for _, path := range []string{%s, %s, %s} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(data))
		for _, needle := range []string{%s, %s, %s, %s, %s, %s} {
			if strings.Contains(lower, needle) {
				return true
			}
		}
	}
	return false
}

func %s() bool {
	for _, path := range []string{%s, %s, %s, %s} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func %s() bool {
	for _, key := range []string{%s, %s, %s} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

func %s() bool {
	if %s() {
		return true
	}
	_ = %s()
	return false
}

func %s() bool {
	if %s() {
		return true
	}
	if %s() {
		return true
	}
	if %s() {
		return true
	}
	return %s()
}
`,
		syms.tampered,
		syms.guardKey, guardKey,
		varDecls.String(),
		syms.decrypt,
		syms.integrity,
		syms.tampered,
		syms.guardKey,
		syms.tampered,
		syms.tracer,
		decodeCalls["goos"],
		decodeCalls["proc-status"],
		decodeCalls["nl"],
		decodeCalls["tracer"],
		syms.parentSusp,
		syms.emuCPU,
		decodeCalls["goos"],
		decodeCalls["proc-cpu"],
		decodeCalls["needle-qemu"], decodeCalls["needle-kvm"], decodeCalls["needle-vcpu"],
		decodeCalls["needle-uemu"], decodeCalls["needle-bochs"], decodeCalls["needle-vbox"],
		decodeCalls["needle-vmware"], decodeCalls["needle-tcg"],
		syms.emuDMI,
		decodeCalls["goos"],
		decodeCalls["dmi-product"], decodeCalls["dmi-vendor"], decodeCalls["dmi-board"],
		decodeCalls["dmi-qemu"], decodeCalls["dmi-bochs"], decodeCalls["dmi-vbox"],
		decodeCalls["dmi-vbox2"], decodeCalls["dmi-vmware"], decodeCalls["dmi-indie"],
		syms.emuDev,
		decodeCalls["dev-qemu"], decodeCalls["dev-gold"], decodeCalls["dev-wsock"], decodeCalls["dev-fw"],
		syms.emuEnv,
		decodeCalls["env-qemu"], decodeCalls["env-under"], decodeCalls["env-unicorn"],
		syms.antiDebug,
		syms.tracer,
		syms.parentSusp,
		syms.antiEmulation,
		syms.emuCPU,
		syms.emuDMI,
		syms.emuDev,
		syms.emuEnv,
	)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "guard.go", src, 0)
	if err != nil {
		panic(err)
	}
	mergeHelperImports(file, f)
	var decls []ast.Decl
	for _, d := range f.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.IMPORT {
			continue
		}
		decls = append(decls, d)
	}
	return decls
}

func mergeHelperImports(dst, src *ast.File) {
	existing := importPaths(dst)
	var specs []ast.Spec
	for _, decl := range src.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		for _, spec := range gd.Specs {
			is, ok := spec.(*ast.ImportSpec)
			if !ok || is.Path == nil {
				continue
			}
			path := is.Path.Value
			if existing[path] {
				continue
			}
			existing[path] = true
			specs = append(specs, &ast.ImportSpec{Path: is.Path, Name: is.Name})
		}
	}
	if len(specs) == 0 {
		return
	}
	for _, decl := range dst.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		gd.Specs = append(gd.Specs, specs...)
		return
	}
	impDecl := &ast.GenDecl{Tok: token.IMPORT, Specs: specs}
	insertAt := declInsertAfterImports(dst)
	dst.Decls = append(dst.Decls[:insertAt], append([]ast.Decl{impDecl}, dst.Decls[insertAt:]...)...)
}

func importPaths(file *ast.File) map[string]bool {
	out := make(map[string]bool)
	for _, imp := range file.Imports {
		if imp.Path != nil {
			out[imp.Path.Value] = true
		}
	}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		for _, spec := range gd.Specs {
			is, ok := spec.(*ast.ImportSpec)
			if !ok || is.Path == nil {
				continue
			}
			out[is.Path.Value] = true
		}
	}
	return out
}

func guardRuntimeExists(file *ast.File, integrityName string) bool {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name != nil && fn.Name.Name == integrityName {
			return true
		}
	}
	return false
}
