package driver

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ai-fuchsia/go-obfuscator/internal/compile"
	execproxy "github.com/ai-fuchsia/go-obfuscator/internal/exec"
	"github.com/ai-fuchsia/go-obfuscator/internal/link"
	"github.com/ai-fuchsia/go-obfuscator/internal/mapfile"
	"github.com/ai-fuchsia/go-obfuscator/internal/reverse"
)

const defaultSeed = "gooverlay-default-seed"

// Run is the main entry point. It dispatches to active mode or toolchain launcher mode.
func Run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}

	toolPath, toolArgs, ok := parseToolInvocation(args)
	if ok {
		return runTool(toolPath, toolArgs)
	}

	switch args[0] {
	case "build", "test", "run":
		return runGoCommand(args[0], args[1:])
	case "reverse":
		return runReverse(args[1:])
	case "map":
		return runMap(args[1:])
	case "help", "-h", "--help":
		return usageError()
	default:
		return fmt.Errorf("unknown command %q\n\n%v", args[0], usageText())
	}
}

func usageError() error {
	return fmt.Errorf("%v", usageText())
}

func usageText() string {
	return `gooverlay — Garble-style Go obfuscator overlay

Usage:
  gooverlay build [flags] [packages]
  gooverlay test  [flags] [packages]
  gooverlay run   [flags] [package] [args...]
  gooverlay reverse [file...]
  gooverlay map

Build flags (Garble-compatible subset):
  -literals              Obfuscate string literals (opt-in, like Garble)
  -tiny                  Strip extra runtime/debug metadata
  -seed=KEY              Deterministic obfuscation seed
  -seed=random           Random seed (printed to stderr)
  -debug                 Write obfuscated sources to debug dir
  -debugdir=PATH         Debug output directory

Extra flags:
  -constants / -no-constants   Numeric constant hiding (default on)
  -mba / -no-mba               MBA rewrites (default on)
  -controlflow / -no-controlflow  Control-flow flattening (default off)
  -virtualize / -no-virtualize     Code virtualization via bytecode VM (default off)
  -junk / -no-junk             Dead code injection (default on)
  -opaque / -no-opaque         Opaque predicates (default on)
  -tamper / -no-tamper         Automatic tamper identification (default on)
  -antidebug / -no-antidebug   Anti-debug checks (default on)
  -antiemulation / -no-antiemulation  Anti-emulation checks (default on)
  -a                           Force rebuild all packages

Environment:
  GOGARBLE / GOOVERLAY     Package glob patterns to obfuscate
  GOOVERLAY_SEED           Obfuscation seed
  GOOVERLAY_MAPFILE        Reversible name map (for reverse/map)
  GOOVERLAY_DEBUGDIR       Obfuscated source output directory
`
}

func parseToolInvocation(args []string) (toolPath string, toolArgs []string, ok bool) {
	if len(args) == 0 {
		return "", nil, false
	}
	first := filepath.Base(args[0])
	switch first {
	case "compile", "asm", "link", "cgo":
		return args[0], args[1:], true
	}
	return "", nil, false
}

func runTool(toolPath string, args []string) error {
	tool := filepath.Base(toolPath)
	switch tool {
	case "compile":
		return compile.Hook(toolPath, args)
	case "link":
		return link.Hook(toolPath, args)
	default:
		return execproxy.Forward(toolPath, args)
	}
}

type buildFlags struct {
	literals      bool
	constants     bool
	mba           bool
	controlFlow   bool
	virtualize    bool
	junk          bool
	opaque        bool
	tamper        bool
	antiDebug     bool
	antiEmulation bool
	tiny          bool
	debug         bool
	debugDir      string
	seed          string
	seedRandom    bool
	forceRebuild  bool
	goArgs        []string
}

func parseBuildFlags(args []string) (buildFlags, error) {
	f := buildFlags{
		constants:   true,
		mba:         true,
		junk:        true,
		opaque:      true,
		tamper:        true,
		antiDebug:     true,
		antiEmulation: true,
		seed:          strings.TrimSpace(os.Getenv("GOOVERLAY_SEED")),
	}
	if f.seed == "" {
		f.seed = defaultSeed
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-literals":
			f.literals = true
		case arg == "-tiny":
			f.tiny = true
		case arg == "-debug":
			f.debug = true
		case arg == "-a":
			f.forceRebuild = true
		case arg == "-constants":
			f.constants = true
		case arg == "-no-constants":
			f.constants = false
		case arg == "-mba":
			f.mba = true
		case arg == "-no-mba":
			f.mba = false
		case arg == "-controlflow":
			f.controlFlow = true
		case arg == "-no-controlflow":
			f.controlFlow = false
		case arg == "-virtualize":
			f.virtualize = true
		case arg == "-no-virtualize":
			f.virtualize = false
		case arg == "-junk":
			f.junk = true
		case arg == "-no-junk":
			f.junk = false
		case arg == "-opaque":
			f.opaque = true
		case arg == "-no-opaque":
			f.opaque = false
		case arg == "-tamper":
			f.tamper = true
		case arg == "-no-tamper":
			f.tamper = false
		case arg == "-antidebug":
			f.antiDebug = true
		case arg == "-no-antidebug":
			f.antiDebug = false
		case arg == "-antiemulation":
			f.antiEmulation = true
		case arg == "-no-antiemulation":
			f.antiEmulation = false
		case strings.HasPrefix(arg, "-seed="):
			val := strings.TrimPrefix(arg, "-seed=")
			if val == "random" {
				f.seedRandom = true
			} else {
				f.seed = val
			}
		case strings.HasPrefix(arg, "-debugdir="):
			f.debugDir = strings.TrimPrefix(arg, "-debugdir=")
			f.debug = true
		default:
			f.goArgs = append(f.goArgs, arg)
		}
	}
	return f, nil
}

func runGoCommand(command string, args []string) error {
	flags, err := parseBuildFlags(args)
	if err != nil {
		return err
	}

	if flags.seedRandom {
		seed, err := randomSeed()
		if err != nil {
			return err
		}
		flags.seed = seed
		fmt.Fprintf(os.Stderr, "gooverlay: random seed: %s\n", seed)
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}

	overlay := os.Getenv("GOGARBLE")
	if overlay == "" {
		overlay = os.Getenv("GOOVERLAY")
	}
	moduleRoot := ""
	if overlay == "" {
		moduleRoot, overlay, err = moduleRootAndPath()
		if err != nil {
			return fmt.Errorf("detect module path: %w (set GOGARBLE manually)", err)
		}
	} else {
		moduleRoot, _, err = moduleRootAndPath()
		if err != nil {
			return fmt.Errorf("detect module root: %w", err)
		}
	}

	mapPath := os.Getenv("GOOVERLAY_MAPFILE")
	if mapPath == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			cacheDir = os.TempDir()
		}
		mapPath = filepath.Join(cacheDir, "gooverlay", "map.json")
		_ = os.MkdirAll(filepath.Dir(mapPath), 0o700)
		_ = os.WriteFile(mapPath, []byte(`{"seed":"","entries":[]}`), 0o600)
	}

	debugDir := flags.debugDir
	if debugDir == "" {
		debugDir = os.Getenv("GOOVERLAY_DEBUGDIR")
	}
	if flags.debug && debugDir == "" {
		debugDir = filepath.Join(os.TempDir(), "gooverlay-debug")
	}

	goArgs := []string{command, "-toolexec=" + self, "-trimpath"}
	if flags.forceRebuild {
		goArgs = append(goArgs, "-a")
	}
	if flags.tiny {
		goArgs = append(goArgs, "-ldflags=-s -w", "-gcflags=all=-l")
	}
	if v := os.Getenv("GOOVERLAY_GOFLAGS"); v != "" {
		goArgs = append(goArgs, strings.Fields(v)...)
	}
	goArgs = append(goArgs, flags.goArgs...)

	cmd := exec.Command("go", goArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = appendEnv(os.Environ(),
		"GOOVERLAY_SEED="+flags.seed,
		"GOGARBLE="+overlay,
		"GOOVERLAY="+overlay,
		"GOOVERLAY_ROOT="+moduleRoot,
		"GOOVERLAY_MAPFILE="+mapPath,
		"GOOVERLAY_DEBUGDIR="+debugDir,
		"GOOVERLAY_LITERALS="+boolEnv(flags.literals),
		"GOOVERLAY_CONSTANTS="+boolEnv(flags.constants),
		"GOOVERLAY_MBA="+boolEnv(flags.mba),
		"GOOVERLAY_CONTROLFLOW="+boolEnv(flags.controlFlow),
		"GOOVERLAY_VIRTUALIZE="+boolEnv(flags.virtualize),
		"GOOVERLAY_JUNK="+boolEnv(flags.junk),
		"GOOVERLAY_OPAQUE="+boolEnv(flags.opaque),
		"GOOVERLAY_TAMPER="+boolEnv(flags.tamper),
		"GOOVERLAY_ANTIDEBUG="+boolEnv(flags.antiDebug),
		"GOOVERLAY_ANTIEMULATION="+boolEnv(flags.antiEmulation),
		"GOOVERLAY_TINY="+boolEnv(flags.tiny),
	)
	return cmd.Run()
}

func runReverse(args []string) error {
	mapPath := os.Getenv("GOOVERLAY_MAPFILE")
	if mapPath == "" {
		cacheDir, _ := os.UserCacheDir()
		if cacheDir == "" {
			cacheDir = os.TempDir()
		}
		mapPath = filepath.Join(cacheDir, "gooverlay", "map.json")
	}
	if len(args) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		out, err := reverse.Text(mapPath, string(data))
		if err != nil {
			return err
		}
		fmt.Print(out)
		return nil
	}
	for _, path := range args {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out, err := reverse.Text(mapPath, string(data))
		if err != nil {
			return err
		}
		fmt.Print(out)
	}
	return nil
}

func runMap(args []string) error {
	mapPath := os.Getenv("GOOVERLAY_MAPFILE")
	if len(args) > 0 {
		mapPath = args[0]
	}
	if mapPath == "" {
		cacheDir, _ := os.UserCacheDir()
		if cacheDir == "" {
			cacheDir = os.TempDir()
		}
		mapPath = filepath.Join(cacheDir, "gooverlay", "map.json")
	}
	f, err := mapfile.Read(mapPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(mapPath)
	if err != nil {
		return err
	}
	_ = f
	fmt.Print(string(data))
	return nil
}

func randomSeed() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func boolEnv(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func appendEnv(base []string, pairs ...string) []string {
	unset := make(map[string]struct{}, len(pairs))
	for _, pair := range pairs {
		key, _, _ := strings.Cut(pair, "=")
		unset[key] = struct{}{}
	}
	out := make([]string, 0, len(base)+len(pairs))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if _, ok := unset[key]; ok {
			continue
		}
		out = append(out, entry)
	}
	return append(out, pairs...)
}

func moduleRootAndPath() (root string, module string, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	for {
		modPath := filepath.Join(wd, "go.mod")
		if _, err := os.Stat(modPath); err == nil {
			module, err := parseModulePath(modPath)
			if err != nil {
				return "", "", err
			}
			return wd, module, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", "", fmt.Errorf("go.mod not found")
		}
		wd = parent
	}
}

func parseModulePath(modFile string) (string, error) {
	f, err := os.Open(modFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
		}
	}
	return "", fmt.Errorf("module directive not found in %s", modFile)
}
