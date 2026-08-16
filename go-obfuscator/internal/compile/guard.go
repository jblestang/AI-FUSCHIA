package compile

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

const (
	guardIntegrityBase     = "__gooverlay_integrity"
	guardAntiDebugBase     = "__gooverlay_antidebug"
	guardAntiEmulationBase = "__gooverlay_antiemulation"
	guardReportBase        = "__gooverlay_report_tamper"
	guardSecurityOKBase    = "__gooverlay_security_ok"
	guardTamperedVar       = "__gooverlay_tampered"
	guardKeyVar            = "__gooverlay_guard_key"
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

	guardKey := hash.Int64(cfg.Seed, pkgPath, "guard:key")
	if decls := injectGuardRuntime(file, guardKey); len(decls) > 0 {
		insertAt := declInsertAfterImports(file)
		for _, d := range decls {
			policies.MarkSkipDecl(d)
		}
		file.Decls = append(file.Decls[:insertAt], append(decls, file.Decls[insertAt:]...)...)
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
			prefix = append(prefix, tamperCheckStmt(cfg, pkgPath, fn.Name.Name, guardKey))
		}
		if antiDebugOn && PassEnabled(cfg, pol, PassAntiDebug) {
			prefix = append(prefix, antiDebugCheckStmt())
		}
		if antiEmulationOn && PassEnabled(cfg, pol, PassAntiEmulation) {
			prefix = append(prefix, antiEmulationCheckStmt())
		}
		if len(prefix) == 0 {
			continue
		}
		fn.Body.List = append(prefix, fn.Body.List...)
	}
}

func tamperCheckStmt(cfg Config, pkgPath, funcName string, guardKey int64) ast.Stmt {
	tag := hash.Int(cfg.Seed, pkgPath, "guard:tag:"+funcName) % 1000000
	expected := int((int64(tag)*31 + guardKey) % 997)
	exitCode := hash.Int(cfg.Seed, pkgPath, "guard:exit:"+funcName)%89 + 10

	return &ast.IfStmt{
		Cond: &ast.UnaryExpr{
			Op: token.NOT,
			X: &ast.CallExpr{
				Fun: ast.NewIdent(guardIntegrityBase),
				Args: []ast.Expr{
					intLit(int64(tag)),
					intLit(int64(expected)),
				},
			},
		},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ExprStmt{X: &ast.CallExpr{
				Fun:  ast.NewIdent(guardReportBase),
				Args: []ast.Expr{intLit(int64(exitCode))},
			}},
		}},
	}
}

func antiDebugCheckStmt() ast.Stmt {
	return &ast.IfStmt{
		Cond: &ast.CallExpr{Fun: ast.NewIdent(guardAntiDebugBase)},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ExprStmt{X: &ast.CallExpr{
				Fun:  ast.NewIdent(guardReportBase),
				Args: []ast.Expr{intLit(98)},
			}},
		}},
	}
}

func antiEmulationCheckStmt() ast.Stmt {
	return &ast.IfStmt{
		Cond: &ast.CallExpr{Fun: ast.NewIdent(guardAntiEmulationBase)},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ExprStmt{X: &ast.CallExpr{
				Fun:  ast.NewIdent(guardReportBase),
				Args: []ast.Expr{intLit(97)},
			}},
		}},
	}
}

func injectGuardRuntime(file *ast.File, guardKey int64) []ast.Decl {
	if guardRuntimeExists(file) {
		return nil
	}
	src := fmt.Sprintf(`package p

import (
	"os"
	"runtime"
	"strings"
)

var %s bool
var %s int64 = %d

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

func __gooverlay_tracerAttached() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return true
			}
		}
	}
	return false
}

func __gooverlay_parentSuspicious() bool {
	ppid := os.Getppid()
	return ppid > 1 && ppid != os.Getpid()
}

func __gooverlay_emulatorCPUInfo() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	for _, needle := range []string{
		"qemu virtual",
		"common kvm processor",
		"virtual cpu",
		"user-mode emulation",
		"bochs",
		"vbox",
		"vmware virtual platform",
		"tcg guest",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func __gooverlay_emulatorDMI() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	for _, path := range []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_vendor",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(data))
		for _, needle := range []string{"qemu", "bochs", "virtualbox", "vbox", "vmware", "independent virtual"} {
			if strings.Contains(lower, needle) {
				return true
			}
		}
	}
	return false
}

func __gooverlay_emulatorDevices() bool {
	for _, path := range []string{
		"/dev/qemu_pipe",
		"/dev/goldfish_pipe",
		"/dev/wsocket",
		"/sys/firmware/qemu_fw_cfg",
	} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func __gooverlay_emulatorEnv() bool {
	for _, key := range []string{"QEMU_ENV", "UNDER_QEMU", "UNICORN_ENGINE"} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

func %s() bool {
	if __gooverlay_tracerAttached() {
		return true
	}
	_ = __gooverlay_parentSuspicious()
	return false
}

func %s() bool {
	if __gooverlay_emulatorCPUInfo() {
		return true
	}
	if __gooverlay_emulatorDMI() {
		return true
	}
	if __gooverlay_emulatorDevices() {
		return true
	}
	return __gooverlay_emulatorEnv()
}

func %s(code int) {
	%s = true
	os.Exit(code)
}

func %s() bool {
	return !%s && !%s() && !%s()
}
`,
		guardTamperedVar,
		guardKeyVar, guardKey,
		guardIntegrityBase,
		guardTamperedVar,
		guardKeyVar,
		guardTamperedVar,
		guardAntiDebugBase,
		guardAntiEmulationBase,
		guardReportBase,
		guardTamperedVar,
		guardSecurityOKBase,
		guardTamperedVar,
		guardAntiDebugBase,
		guardAntiEmulationBase,
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

func guardRuntimeExists(file *ast.File) bool {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name != nil && fn.Name.Name == guardIntegrityBase {
			return true
		}
	}
	return false
}
