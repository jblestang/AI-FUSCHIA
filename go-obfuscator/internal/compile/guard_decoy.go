package compile

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

func injectGuardDecoys(cfg Config, pkgPath string, file *ast.File, syms guardSymbols, batch string) []ast.Decl {
	if guardDecoysExist(file, cfg, pkgPath, batch) {
		return nil
	}
	prefix := "guard:decoy:"
	if batch != "" {
		prefix = "guard:decoy:" + batch + ":"
	}

	baitStrings := []guardStringEntry{
		{ctx: "decoy0-name", plain: "__gooverlay_integrity"},
		{ctx: "decoy1-name", plain: "__gooverlay_report_tamper"},
		{ctx: "decoy2-name", plain: "__gooverlay_antidebug"},
		{ctx: "decoy3-path", plain: "/proc/self/maps"},
		{ctx: "decoy4-path", plain: "/proc/self/auxv"},
		{ctx: "decoy5-env", plain: "LD_PRELOAD"},
		{ctx: "decoy6-env", plain: "FRIDA_AGENT"},
		{ctx: "decoy7-needle", plain: "frida"},
		{ctx: "decoy8-needle", plain: "gdb"},
		{ctx: "decoy9-path", plain: "/sys/devices/virtual/dmi/id/product_name"},
	}

	var varDecls strings.Builder
	decodeCalls := make(map[string]string)
	for _, entry := range baitStrings {
		key := hash.Bytes(cfg.Seed, pkgPath, prefix+"skey:"+entry.ctx, 8)
		enc := xorEncode(entry.plain, key)
		encVar := hash.Name(cfg.Seed, pkgPath, prefix+"enc:"+entry.ctx)
		keyVar := hash.Name(cfg.Seed, pkgPath, prefix+"k:"+entry.ctx)
		fmt.Fprintf(&varDecls, "\t%s = %s\n\t%s = %s\n", encVar, formatByteSlice(enc), keyVar, formatByteSlice(key))
		decodeCalls[entry.ctx] = fmt.Sprintf("%s(%s, %s)", syms.decrypt, encVar, keyVar)
	}

	decoyTampered := hash.Name(cfg.Seed, pkgPath, prefix+"tampered")
	decoyKey := hash.Int64(cfg.Seed, pkgPath, prefix+"key")
	names := makeDecoyFuncNames(cfg, pkgPath, batch)

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

func %s(tag, expected int) bool {
	if %s {
		return false
	}
	actual := int((int64(tag)*17 + %s) %% 991)
	ok := actual == expected
	if !ok {
		%s = true
	}
	return ok
}

func %s() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile(%s)
	if err != nil {
		return false
	}
	needle := %s
	return strings.Contains(strings.ToLower(string(data)), needle)
}

func %s() bool {
	for _, key := range []string{%s, %s} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	if _, err := os.Stat(%s); err == nil {
		return true
	}
	return false
}

func %s(code int) {
	%s = true
	_ = %s
	os.Exit(code)
}

func %s() bool {
	return %s() || %s() || %s(0, 0)
}
`,
		decoyTampered,
		hash.Name(cfg.Seed, pkgPath, prefix+"keyvar"), decoyKey,
		varDecls.String(),
		names.integrity,
		decoyTampered,
		hash.Name(cfg.Seed, pkgPath, prefix+"keyvar"),
		decoyTampered,
		names.antiDebug,
		decodeCalls["decoy3-path"],
		decodeCalls["decoy7-needle"],
		names.antiEmu,
		decodeCalls["decoy5-env"], decodeCalls["decoy6-env"],
		decodeCalls["decoy4-path"],
		names.report,
		decoyTampered,
		decodeCalls["decoy1-name"],
		names.securityOK,
		names.antiDebug,
		names.antiEmu,
		names.integrity,
	)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "guard_decoy.go", src, 0)
	if err != nil {
		panic(err)
	}

	var decls []ast.Decl
	for _, d := range f.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.IMPORT {
			continue
		}
		decls = append(decls, d)
	}
	return decls
}

type decoyGuardNames struct {
	integrity  string
	antiDebug  string
	antiEmu    string
	report     string
	securityOK string
}

func makeDecoyFuncNames(cfg Config, pkgPath, batch string) decoyGuardNames {
	prefix := "guard:decoy:"
	if batch != "" {
		prefix = "guard:decoy:" + batch + ":"
	}
	return decoyGuardNames{
		integrity:  hash.Name(cfg.Seed, pkgPath, prefix+"integrity"),
		antiDebug:  hash.Name(cfg.Seed, pkgPath, prefix+"antidebug"),
		antiEmu:    hash.Name(cfg.Seed, pkgPath, prefix+"antiemu"),
		report:     hash.Name(cfg.Seed, pkgPath, prefix+"report"),
		securityOK: hash.Name(cfg.Seed, pkgPath, prefix+"secok"),
	}
}

func guardDecoysExist(file *ast.File, cfg Config, pkgPath, batch string) bool {
	name := makeDecoyFuncNames(cfg, pkgPath, batch).integrity
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name != nil && fn.Name.Name == name {
			return true
		}
	}
	return false
}
