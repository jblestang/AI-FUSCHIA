package compile_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go/parser"
	"go/token"

	"github.com/ai-fuchsia/go-obfuscator/internal/compile"
)

func TestRenameExampleSource(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(moduleRoot(t), "example", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", string(src), parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	out, err := compile.RenameFile(compile.Config{Seed: "seed"}, "github.com/ai-fuchsia/go-obfuscator/example", file, fset)
	if err != nil {
		t.Fatalf("rename failed: %v", err)
	}
	if strings.Contains(out, "formatBanner") {
		t.Fatalf("expected formatBanner renamed:\n%s", out)
	}
}

func TestPrepareCompileFromModuleRelativePath(t *testing.T) {
	root := moduleRoot(t)
	t.Setenv("GOOVERLAY", "github.com/ai-fuchsia/go-obfuscator")
	t.Setenv("GOOVERLAY_ROOT", root)

	args := []string{
		"-o", "/tmp/out.a",
		"-p", "main",
		"-complete",
		"-pack",
		"example/main.go",
	}

	newArgs, err := compile.PrepareCompile(compile.Config{Seed: "seed"}, "github.com/ai-fuchsia/go-obfuscator/example", args)
	if err != nil {
		t.Fatal(err)
	}
	last := newArgs[len(newArgs)-1]
	data, err := os.ReadFile(last)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "formatBanner") {
		t.Fatalf("expected renamed source")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
