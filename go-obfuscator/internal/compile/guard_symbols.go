package compile

import (
	"fmt"

	"github.com/ai-fuchsia/go-obfuscator/internal/hash"
)

type guardSymbols struct {
	tampered      string
	guardKey      string
	integrity     string
	antiDebug     string
	antiEmulation string
	decrypt       string
	tracer        string
	parentSusp    string
	emuCPU        string
	emuDMI        string
	emuDev        string
	emuEnv        string
}

func guardSymbolsFor(cfg Config, pkgPath string) guardSymbols {
	return guardSymbols{
		tampered:      hash.Name(cfg.Seed, pkgPath, "guard:tampered"),
		guardKey:      hash.Name(cfg.Seed, pkgPath, "guard:keyvar"),
		integrity:     hash.Name(cfg.Seed, pkgPath, "guard:integrity"),
		antiDebug:     hash.Name(cfg.Seed, pkgPath, "guard:antidebug"),
		antiEmulation: hash.Name(cfg.Seed, pkgPath, "guard:antiemu"),
		decrypt:       hash.Name(cfg.Seed, pkgPath, "guard:decrypt"),
		tracer:        hash.Name(cfg.Seed, pkgPath, "guard:tracer"),
		parentSusp:    hash.Name(cfg.Seed, pkgPath, "guard:parent"),
		emuCPU:        hash.Name(cfg.Seed, pkgPath, "guard:emucpu"),
		emuDMI:        hash.Name(cfg.Seed, pkgPath, "guard:emudmi"),
		emuDev:        hash.Name(cfg.Seed, pkgPath, "guard:emudev"),
		emuEnv:        hash.Name(cfg.Seed, pkgPath, "guard:emuenv"),
	}
}

func xorEncode(plain string, key []byte) []byte {
	enc := make([]byte, len(plain))
	for i := range plain {
		enc[i] = plain[i] ^ key[i%len(key)]
	}
	return enc
}

func formatByteSlice(b []byte) string {
	if len(b) == 0 {
		return "nil"
	}
	out := "[]byte{"
	for i, v := range b {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%d", v)
	}
	out += "}"
	return out
}
