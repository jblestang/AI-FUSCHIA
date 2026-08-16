package compile

import (
	"go/ast"
	"strings"
)

const directivePrefix = "gooverlay:"

// PassName identifies an obfuscation pass for directives.
type PassName string

const (
	PassLiterals    PassName = "literals"
	PassConstants   PassName = "constants"
	PassMBA         PassName = "mba"
	PassControlFlow PassName = "controlflow"
	PassVirtualize  PassName = "virtualize"
	PassJunk        PassName = "junk"
	PassOpaque      PassName = "opaque"
	PassTamper        PassName = "tamper"
	PassAntiDebug     PassName = "antidebug"
	PassAntiEmulation PassName = "antiemulation"
	PassMultipath     PassName = "multipath"
)

// PassOverride is nil = inherit global/defaults, true/false = force.
type PassOverride struct {
	SkipAll    bool
	Literals   *bool
	Constants  *bool
	MBA        *bool
	ControlFlow *bool
	Virtualize *bool
	Junk       *bool
	Opaque     *bool
	Tamper        *bool
	AntiDebug     *bool
	AntiEmulation *bool
	Multipath     *bool
}

// FilePolicies holds parsed //gooverlay: directives from AST comments.
type FilePolicies struct {
	File     PassOverride
	ByFunc   map[*ast.FuncDecl]PassOverride
	skipDecl map[ast.Decl]struct{}
}

// MarkSkipDecl excludes a declaration from later obfuscation passes (runtime stubs).
func (p *FilePolicies) MarkSkipDecl(d ast.Decl) {
	if p.skipDecl == nil {
		p.skipDecl = make(map[ast.Decl]struct{})
	}
	p.skipDecl[d] = struct{}{}
}

func (p *FilePolicies) ShouldSkipDecl(d ast.Decl) bool {
	if p == nil || p.skipDecl == nil {
		return false
	}
	_, ok := p.skipDecl[d]
	return ok
}

// ParseDirectives scans file and function doc comments (must run before stripComments).
func ParseDirectives(file *ast.File) *FilePolicies {
	p := &FilePolicies{ByFunc: make(map[*ast.FuncDecl]PassOverride), skipDecl: make(map[ast.Decl]struct{})}
	if file.Doc != nil {
		p.File = parseOverride(file.Doc)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Doc == nil {
			continue
		}
		p.ByFunc[fn] = mergeOverride(p.File, parseOverride(fn.Doc))
	}
	return p
}

func parseOverride(group *ast.CommentGroup) PassOverride {
	var o PassOverride
	for _, c := range group.List {
		text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
		text = strings.TrimSuffix(text, "*/")
		if !strings.HasPrefix(text, directivePrefix) {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(text, directivePrefix))
		if body == "" {
			continue
		}
		applyTokens(&o, strings.Fields(body))
	}
	return o
}

func applyTokens(o *PassOverride, tokens []string) {
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, "no-") || strings.HasPrefix(tok, "no_") {
			setPass(o, strings.TrimPrefix(strings.TrimPrefix(tok, "no-"), "no_"), false)
			continue
		}
		switch tok {
		case "off", "skip", "plain":
			o.SkipAll = true
		case "file":
			// file-level marker only; tokens after handled separately
		case "max", "harden", "protect", "license":
			applyMaxOverride(o)
		default:
			setPass(o, tok, true)
		}
	}
}

func setPass(o *PassOverride, name string, on bool) {
	switch PassName(name) {
	case PassLiterals:
		o.Literals = &on
	case PassConstants:
		o.Constants = &on
	case PassMBA:
		o.MBA = &on
	case PassControlFlow, "cf", "control-flow":
		onCF := on
		o.ControlFlow = &onCF
	case PassVirtualize, "vm":
		onV := on
		o.Virtualize = &onV
	case PassJunk:
		o.Junk = &on
	case PassOpaque:
		o.Opaque = &on
	case PassTamper, "integrity":
		onT := on
		o.Tamper = &onT
	case PassAntiDebug, "anti-debug":
		onA := on
		o.AntiDebug = &onA
	case PassAntiEmulation, "anti-emulation", "emulation":
		onE := on
		o.AntiEmulation = &onE
	case PassMultipath, "multi-path":
		onM := on
		o.Multipath = &onM
	}
}

func mergeOverride(base, extra PassOverride) PassOverride {
	out := base
	if extra.SkipAll {
		out.SkipAll = true
	}
	out.Literals = coalesceBool(out.Literals, extra.Literals)
	out.Constants = coalesceBool(out.Constants, extra.Constants)
	out.MBA = coalesceBool(out.MBA, extra.MBA)
	out.ControlFlow = coalesceBool(out.ControlFlow, extra.ControlFlow)
	out.Virtualize = coalesceBool(out.Virtualize, extra.Virtualize)
	out.Junk = coalesceBool(out.Junk, extra.Junk)
	out.Opaque = coalesceBool(out.Opaque, extra.Opaque)
	out.Tamper = coalesceBool(out.Tamper, extra.Tamper)
	out.AntiDebug = coalesceBool(out.AntiDebug, extra.AntiDebug)
	out.AntiEmulation = coalesceBool(out.AntiEmulation, extra.AntiEmulation)
	out.Multipath = coalesceBool(out.Multipath, extra.Multipath)
	return out
}

func coalesceBool(a, b *bool) *bool {
	if b != nil {
		return b
	}
	return a
}

// ForFunc returns effective overrides for a function (file defaults + func doc).
func (p *FilePolicies) ForFunc(fn *ast.FuncDecl) PassOverride {
	if fn == nil {
		return p.File
	}
	if o, ok := p.ByFunc[fn]; ok {
		return o
	}
	return p.File
}

// PassEnabled combines global config with per-function overrides.
func PassEnabled(cfg Config, o PassOverride, pass PassName) bool {
	if o.SkipAll {
		return false
	}
	switch pass {
	case PassLiterals:
		return pick(o.Literals, cfg.Literals)
	case PassConstants:
		return pick(o.Constants, cfg.Constants)
	case PassMBA:
		return pick(o.MBA, cfg.MBA)
	case PassControlFlow:
		return pick(o.ControlFlow, cfg.ControlFlow)
	case PassVirtualize:
		return pick(o.Virtualize, cfg.Virtualize)
	case PassJunk:
		return pick(o.Junk, cfg.Junk)
	case PassOpaque:
		return pick(o.Opaque, cfg.Opaque)
	case PassTamper:
		return pick(o.Tamper, cfg.Tamper)
	case PassAntiDebug:
		return pick(o.AntiDebug, cfg.AntiDebug)
	case PassAntiEmulation:
		return pick(o.AntiEmulation, cfg.AntiEmulation)
	case PassMultipath:
		return pick(o.Multipath, cfg.Multipath)
	default:
		return false
	}
}

func pick(override *bool, global bool) bool {
	if override != nil {
		return *override
	}
	return global
}

// StripDirectiveComments removes //gooverlay: lines from docs (after parsing).
func StripDirectiveComments(file *ast.File) {
	if file.Doc != nil {
		file.Doc = filterDoc(file.Doc)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Doc == nil {
			continue
		}
		fn.Doc = filterDoc(fn.Doc)
		if fn.Doc == nil {
			fn.Doc = nil
		}
	}
}

func filterDoc(group *ast.CommentGroup) *ast.CommentGroup {
	if group == nil {
		return nil
	}
	out := &ast.CommentGroup{}
	for _, c := range group.List {
		text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		if strings.HasPrefix(text, directivePrefix) {
			continue
		}
		out.List = append(out.List, c)
	}
	if len(out.List) == 0 {
		return nil
	}
	return out
}
