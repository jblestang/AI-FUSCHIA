package compile

import (
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

const (
	vmNop       byte = 0
	vmLoadArg   byte = 1
	vmLoadGlob  byte = 2
	vmLoadConst byte = 3
	vmAdd       byte = 16
	vmSub       byte = 17
	vmMul       byte = 18
	vmDiv       byte = 19
	vmNeg       byte = 20
	vmReturn    byte = 255
)

type vmProgram struct {
	code    []byte
	globals []string
}

type vmUnit struct {
	fn   *ast.FuncDecl
	prog *vmProgram
}

type vmCompiler struct {
	seed     string
	pkgPath  string
	funcName string
	params   map[string]int
	globals  []string
	code     []byte
	emitIdx  int
}

func virtualizeFunctions(cfg Config, pkgPath string, file *ast.File, policies *FilePolicies) {
	if policies == nil {
		policies = &FilePolicies{}
	}
	vmName := hash.Name(cfg.Seed, pkgPath, "__gooverlay_vm")
	var units []vmUnit

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name == nil {
			continue
		}
		if fn.Name.Name == "main" || fn.Name.Name == "init" || fn.Recv != nil {
			continue
		}
		if !PassEnabled(cfg, policies.ForFunc(fn), PassVirtualize) {
			continue
		}
		if !returnsInt(fn) {
			continue
		}
		prog, err := compileToVM(cfg.Seed, pkgPath, fn.Name.Name, fn)
		if err != nil {
			continue
		}
		units = append(units, vmUnit{fn: fn, prog: prog})
	}
	if len(units) == 0 {
		return
	}

	insertAt := declInsertAfterImports(file)
	newDecls := make([]ast.Decl, 0, len(units)*3+1)
	for _, u := range units {
		for _, d := range vmDataDecls(cfg, pkgPath, u.fn.Name.Name, u.prog) {
			policies.MarkSkipDecl(d)
			newDecls = append(newDecls, d)
		}
	}
	vmDecl := injectVMInterpreterDecl(vmName)
	policies.MarkSkipDecl(vmDecl)
	newDecls = append(newDecls, vmDecl)
	file.Decls = append(file.Decls[:insertAt], append(newDecls, file.Decls[insertAt:]...)...)

	for _, u := range units {
		u.fn.Body = virtualizedCallBody(cfg, pkgPath, u.fn, u.prog, vmName)
		policies.MarkSkipDecl(u.fn)
	}
}

func declInsertAfterImports(file *ast.File) int {
	insertAt := 0
	for insertAt < len(file.Decls) {
		if gd, ok := file.Decls[insertAt].(*ast.GenDecl); ok && gd.Tok == token.IMPORT {
			insertAt++
			continue
		}
		break
	}
	return insertAt
}

func returnsInt(fn *ast.FuncDecl) bool {
	if fn.Type == nil || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	return ok && ident.Name == "int"
}

func compileToVM(seed, pkgPath, funcName string, fn *ast.FuncDecl) (*vmProgram, error) {
	c := &vmCompiler{
		seed: seed, pkgPath: pkgPath, funcName: funcName,
		params: make(map[string]int),
	}
	if fn.Type != nil && fn.Type.Params != nil {
		idx := 0
		for _, field := range fn.Type.Params.List {
			for _, id := range field.Names {
				if id.Name != "_" {
					c.params[id.Name] = idx
				}
				idx++
			}
			if len(field.Names) == 0 {
				idx++
			}
		}
	}
	ret, ok := singleReturn(fn.Body)
	if !ok || len(ret) != 1 {
		return nil, fmt.Errorf("unsupported body")
	}
	if err := c.compileExpr(ret[0]); err != nil {
		return nil, err
	}
	c.emit(vmReturn)
	return &vmProgram{code: c.code, globals: c.globals}, nil
}

func singleReturn(body *ast.BlockStmt) ([]ast.Expr, bool) {
	if body == nil || len(body.List) != 1 {
		return nil, false
	}
	ret, ok := body.List[0].(*ast.ReturnStmt)
	if !ok {
		return nil, false
	}
	return ret.Results, true
}

func (c *vmCompiler) globalIndex(name string) int {
	for i, g := range c.globals {
		if g == name {
			return i
		}
	}
	c.globals = append(c.globals, name)
	return len(c.globals) - 1
}

func (c *vmCompiler) keyByte(offset int) byte {
	k := hash.Bytes(c.seed, c.pkgPath, "vm:key:"+c.funcName, 16)
	if len(k) == 0 {
		return 0x5a
	}
	return k[offset%len(k)]
}

func (c *vmCompiler) emit(op byte, payload ...byte) {
	if c.maybeEmitFictional() {
		c.emitRaw(vmNop, byte(hash.Int(c.seed, c.pkgPath, fmt.Sprintf("vm:fic:%s:%d", c.funcName, c.emitIdx))%255))
		c.emitIdx++
	}
	c.emitRaw(op, payload...)
}

func (c *vmCompiler) maybeEmitFictional() bool {
	return hash.Int(c.seed, c.pkgPath, fmt.Sprintf("vm:fic:do:%s:%d", c.funcName, c.emitIdx))%3 == 0
}

func (c *vmCompiler) emitRaw(op byte, payload ...byte) {
	plain := append([]byte{op}, payload...)
	base := len(c.code)
	for i, b := range plain {
		c.code = append(c.code, b^c.keyByte(base+i))
	}
	c.emitIdx++
}

func (c *vmCompiler) compileExpr(expr ast.Expr) error {
	switch e := expr.(type) {
	case *ast.Ident:
		if idx, ok := c.params[e.Name]; ok {
			c.emit(vmLoadArg, byte(idx))
			return nil
		}
		c.emit(vmLoadGlob, byte(c.globalIndex(e.Name)))
		return nil
	case *ast.BasicLit:
		if e.Kind != token.INT {
			return fmt.Errorf("unsupported literal")
		}
		v, err := strconv.ParseInt(e.Value, 0, 64)
		if err != nil {
			return err
		}
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(v))
		c.emit(vmLoadConst, buf[:]...)
		return nil
	case *ast.UnaryExpr:
		if e.Op != token.SUB {
			return fmt.Errorf("unsupported unary")
		}
		if err := c.compileExpr(e.X); err != nil {
			return err
		}
		c.emit(vmNeg)
		return nil
	case *ast.BinaryExpr:
		if err := c.compileExpr(e.X); err != nil {
			return err
		}
		if err := c.compileExpr(e.Y); err != nil {
			return err
		}
		switch e.Op {
		case token.ADD:
			c.emit(vmAdd)
		case token.SUB:
			c.emit(vmSub)
		case token.MUL:
			c.emit(vmMul)
		case token.QUO:
			c.emit(vmDiv)
		default:
			return fmt.Errorf("unsupported binop")
		}
		return nil
	case *ast.ParenExpr:
		return c.compileExpr(e.X)
	default:
		return fmt.Errorf("unsupported expr %T", expr)
	}
}

func vmDataDecls(cfg Config, pkgPath, funcName string, prog *vmProgram) []ast.Decl {
	codeName := hash.Name(cfg.Seed, pkgPath, "vm:code:"+funcName)
	keyName := hash.Name(cfg.Seed, pkgPath, "vm:bckey:"+funcName)
	globName := hash.Name(cfg.Seed, pkgPath, "vm:glob:"+funcName)

	key := hash.Bytes(cfg.Seed, pkgPath, "vm:key:"+funcName, 16)
	if len(key) == 0 {
		key = []byte{0x5a}
	}

	codeElts := byteSliceElts(prog.code)
	keyElts := byteSliceElts(key)

	decls := []ast.Decl{
		&ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names:  []*ast.Ident{ast.NewIdent(codeName)},
					Values: []ast.Expr{byteSliceComposite(codeElts)},
				},
				&ast.ValueSpec{
					Names:  []*ast.Ident{ast.NewIdent(keyName)},
					Values: []ast.Expr{byteSliceComposite(keyElts)},
				},
			},
		},
	}

	if len(prog.globals) > 0 {
		globElts := make([]ast.Expr, len(prog.globals))
		for i, g := range prog.globals {
			globElts[i] = ast.NewIdent(g)
		}
		decls = append(decls, &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{&ast.ValueSpec{
				Names: []*ast.Ident{ast.NewIdent(globName)},
				Values: []ast.Expr{&ast.CompositeLit{
					Type: &ast.ArrayType{Len: nil, Elt: ast.NewIdent("int")},
					Elts: globElts,
				}},
			}},
		})
	} else {
		decls = append(decls, &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{&ast.ValueSpec{
				Names:  []*ast.Ident{ast.NewIdent(globName)},
				Values: []ast.Expr{&ast.CompositeLit{Type: &ast.ArrayType{Len: nil, Elt: ast.NewIdent("int")}}},
			}},
		})
	}
	return decls
}

func byteSliceElts(data []byte) []ast.Expr {
	elts := make([]ast.Expr, len(data))
	for i, b := range data {
		elts[i] = intLit(int64(b))
	}
	return elts
}

func byteSliceComposite(elts []ast.Expr) ast.Expr {
	return &ast.CompositeLit{
		Type: &ast.ArrayType{Len: nil, Elt: ast.NewIdent("byte")},
		Elts: elts,
	}
}

func virtualizedCallBody(cfg Config, pkgPath string, fn *ast.FuncDecl, prog *vmProgram, vmName string) *ast.BlockStmt {
	codeName := hash.Name(cfg.Seed, pkgPath, "vm:code:"+fn.Name.Name)
	keyName := hash.Name(cfg.Seed, pkgPath, "vm:bckey:"+fn.Name.Name)
	globName := hash.Name(cfg.Seed, pkgPath, "vm:glob:"+fn.Name.Name)

	args := make([]ast.Expr, 0, len(fn.Type.Params.List)+3)
	args = append(args, ast.NewIdent(keyName), ast.NewIdent(codeName), ast.NewIdent(globName))
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			for _, id := range field.Names {
				args = append(args, ast.NewIdent(id.Name))
			}
		}
	}

	return &ast.BlockStmt{List: []ast.Stmt{&ast.ReturnStmt{Results: []ast.Expr{
		&ast.CallExpr{Fun: ast.NewIdent(vmName), Args: args},
	}}}}
}

func injectVMInterpreterDecl(vmName string) ast.Decl {
	body := `{
		ip := 0
		var stack []int
		var chkStack []uint64
		chkPush := func(v int) uint64 {
			return uint64(v)*0x9e3779b9 + 0x85ebca6b
		}
		for ip < len(code) {
			op := code[ip] ^ key[ip%len(key)]
			ip++
			switch op {
			case 0:
				_ = int(code[ip] ^ key[ip%len(key)])
				ip++
			case 1:
				idx := int(code[ip] ^ key[ip%len(key)])
				ip++
				if idx < 0 || idx >= len(args) {
					return 0
				}
				v := args[idx]
				stack = append(stack, v)
				chkStack = append(chkStack, chkPush(v))
			case 2:
				idx := int(code[ip] ^ key[ip%len(key)])
				ip++
				if idx < 0 || idx >= len(globals) {
					return 0
				}
				v := globals[idx]
				stack = append(stack, v)
				chkStack = append(chkStack, chkPush(v))
			case 3:
				var v uint64
				for j := 0; j < 8; j++ {
					if ip >= len(code) {
						return 0
					}
					v |= uint64(code[ip]^key[ip%len(key)]) << (8 * j)
					ip++
				}
				iv := int(v)
				stack = append(stack, iv)
				chkStack = append(chkStack, chkPush(iv))
			case 16:
				if len(stack) < 2 {
					return 0
				}
				b := stack[len(stack)-1]
				cb := chkStack[len(chkStack)-1]
				stack = stack[:len(stack)-1]
				chkStack = chkStack[:len(chkStack)-1]
				a := stack[len(stack)-1]
				ca := chkStack[len(chkStack)-1]
				r := a + b
				stack[len(stack)-1] = r
				chkStack[len(chkStack)-1] = ca + cb + uint64(r)
			case 17:
				if len(stack) < 2 {
					return 0
				}
				b := stack[len(stack)-1]
				cb := chkStack[len(chkStack)-1]
				stack = stack[:len(stack)-1]
				chkStack = chkStack[:len(chkStack)-1]
				a := stack[len(stack)-1]
				ca := chkStack[len(chkStack)-1]
				r := a - b
				stack[len(stack)-1] = r
				chkStack[len(chkStack)-1] = ca - cb + uint64(r)
			case 18:
				if len(stack) < 2 {
					return 0
				}
				b := stack[len(stack)-1]
				cb := chkStack[len(chkStack)-1]
				stack = stack[:len(stack)-1]
				chkStack = chkStack[:len(chkStack)-1]
				a := stack[len(stack)-1]
				ca := chkStack[len(chkStack)-1]
				r := a * b
				stack[len(stack)-1] = r
				chkStack[len(chkStack)-1] = ca*cb + uint64(r)
			case 19:
				if len(stack) < 2 || stack[len(stack)-1] == 0 {
					return 0
				}
				b := stack[len(stack)-1]
				cb := chkStack[len(chkStack)-1]
				stack = stack[:len(stack)-1]
				chkStack = chkStack[:len(chkStack)-1]
				a := stack[len(stack)-1]
				ca := chkStack[len(chkStack)-1]
				r := a / b
				stack[len(stack)-1] = r
				chkStack[len(chkStack)-1] = ca/cb + uint64(r)
			case 20:
				if len(stack) < 1 {
					return 0
				}
				a := stack[len(stack)-1]
				ca := chkStack[len(chkStack)-1]
				r := -a
				stack[len(stack)-1] = r
				chkStack[len(chkStack)-1] = ^ca + uint64(r)
			case 255:
				if len(stack) < 1 {
					return 0
				}
				return stack[len(stack)-1]
			}
		}
		return 0
	}`
	return parseVMFunc(vmName, body)
}

func parseVMFunc(name, bodySrc string) ast.Decl {
	src := fmt.Sprintf("package p\nfunc %s(key []byte, code []byte, globals []int, args ...int) int %s", name, bodySrc)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "vm.go", src, 0)
	if err != nil {
		panic(err)
	}
	return f.Decls[0].(*ast.FuncDecl)
}

// VirtualizeFunctionsInFile applies virtualization for tests.
func VirtualizeFunctionsInFile(cfg Config, pkgPath string, file *ast.File) {
	virtualizeFunctions(cfg, pkgPath, file, ParseDirectives(file))
}
