package compile

import (
	"os"
	"path/filepath"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
	"github.com/ai-fuchsia/go-obfuscator/internal/mapfile"
)

const overlayPipelineVersion = "guard-v5"

func obfuscatedFilePath(cfg Config, importPath, srcPath string) (string, error) {
	base := filepath.Base(srcPath)
	hashedBase := hash.Name(cfg.Seed, importPath, "file:"+base) + ".go"
	if cfg.Tiny {
		hashedBase = hash.Name(cfg.Seed, importPath, "tiny:file:"+base) + ".go"
	}
	dir := filepath.Join(os.TempDir(), hash.Name(cfg.Seed, importPath, "pkgdir:"+overlayPipelineVersion))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	outPath := filepath.Join(dir, hashedBase)
	if cfg.MapFile != "" {
		_ = mapfile.Record(cfg.MapFile, cfg.Seed, importPath, "file", base, hashedBase)
	}
	return outPath, nil
}

func ensureTrimpath(flags []string, tiny bool) []string {
	hasTrimpath := false
	for _, f := range flags {
		if f == "-trimpath" || stringsHasPrefix(f, "-trimpath=") {
			hasTrimpath = true
			break
		}
	}
	if hasTrimpath {
		return flags
	}
	if tiny {
		return append(flags, "-trimpath")
	}
	return flags
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func debugWrite(cfg Config, importPath, srcPath, content string) error {
	if cfg.DebugDir == "" {
		return nil
	}
	rel := hash.Name(cfg.Seed, importPath, "debug:"+filepath.Base(srcPath))
	path := filepath.Join(cfg.DebugDir, importPath, rel+".go")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}
