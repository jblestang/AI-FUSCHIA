package link

import (
	"os"
	"strings"

	execproxy "github.com/ai-fuchsia/go-obfuscator/internal/exec"
)

// Hook intercepts link invocations and strips debug symbols.
func Hook(toolPath string, args []string) error {
	tiny := os.Getenv("GOOVERLAY_TINY") == "1"
	args = ensureStripFlags(args, tiny)
	return execproxy.Forward(toolPath, args)
}

func ensureStripFlags(args []string, tiny bool) []string {
	hasS := false
	hasW := false
	hasBuildID := false
	for _, arg := range args {
		switch arg {
		case "-s":
			hasS = true
		case "-w":
			hasW = true
		default:
			if strings.HasPrefix(arg, "-buildid") {
				hasBuildID = true
			}
		}
	}

	insert := make([]string, 0, 4)
	if !hasS {
		insert = append(insert, "-s")
	}
	if !hasW {
		insert = append(insert, "-w")
	}
	if !hasBuildID {
		insert = append(insert, "-buildid=")
	}
	if tiny {
		// Best-effort tiny mode without linker patches (Garble patches the linker).
		insert = append(insert, "-X=runtime/debug.buildInfo=")
	}
	if len(insert) == 0 {
		return args
	}

	out := make([]string, 0, len(args)+len(insert))
	pos := 0
	for pos < len(args) && strings.HasPrefix(args[pos], "-") {
		out = append(out, args[pos])
		if needsLinkValue(args[pos]) && pos+1 < len(args) {
			pos++
			out = append(out, args[pos])
		}
		pos++
	}
	out = append(out, insert...)
	out = append(out, args[pos:]...)
	return out
}

func needsLinkValue(flag string) bool {
	switch flag {
	case "-o", "-importcfg", "-buildmode", "-buildid", "-extld", "-extldflags",
		"-tmpdir", "-r", "-R", "-E", "-H", "-I", "-L", "-T", "-X", "-k",
		"-pluginpath", "-libgcc", "-linkmode", "-benchmark", "-benchmarkprofile",
		"-cpuprofile", "-memprofile", "-memprofilerate", "-extar", "-capturehostobjs",
		"-debugtextsize", "-debugtramp", "-strictdups", "-B":
		return true
	}
	return false
}
