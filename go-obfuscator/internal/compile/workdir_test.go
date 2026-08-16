package compile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ai-fuchsia/go-obfuscator/internal/compile"
)

func TestPrepareCompileRealBuildArgs(t *testing.T) {
	root := moduleRoot(t)
	t.Setenv("GOOVERLAY", "github.com/ai-fuchsia/go-obfuscator")
	t.Setenv("GOOVERLAY_ROOT", root)

	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	wd, err := os.MkdirTemp("", "gooverlay-b001")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(wd)
	defer os.Chdir(orig)

	if err := os.MkdirAll(filepath.Join(wd, "example"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wd, "example", "main.go"), []byte("package main\nfunc broken-"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(wd); err != nil {
		t.Fatal(err)
	}

	args := []string{
		"-o", filepath.Join(wd, "_pkg_.a"),
		"-trimpath", wd + "=>",
		"-p", "main",
		"-lang=go1.22",
		"-complete",
		"-buildid", "test",
		"-goversion", "go1.22.2",
		"-c=4",
		"-nolocalimports",
		"-importcfg", filepath.Join(wd, "importcfg"),
		"-pack",
		"./example/main.go",
	}

	if _, err := compile.PrepareCompile(compile.Config{Seed: "seed"}, "github.com/ai-fuchsia/go-obfuscator/example", args); err != nil {
		t.Fatal(err)
	}
}
