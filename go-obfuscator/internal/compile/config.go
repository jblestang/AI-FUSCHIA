package compile

import (
	"os"
	"strings"
)

const defaultSeed = "gooverlay-default-seed"

// Config controls which obfuscation passes run during compile.
type Config struct {
	Seed        string
	MapFile     string
	DebugDir    string
	Literals    bool
	Constants   bool
	MBA         bool
	ControlFlow bool
	Virtualize  bool
	Junk        bool
	Opaque      bool
	Tiny        bool
	StripComments bool
}

// ConfigFromEnv reads obfuscation settings from the environment.
func ConfigFromEnv() Config {
	seed := os.Getenv("GOOVERLAY_SEED")
	if seed == "" {
		seed = defaultSeed
	}
	return Config{
		Seed:          seed,
		MapFile:       os.Getenv("GOOVERLAY_MAPFILE"),
		DebugDir:      os.Getenv("GOOVERLAY_DEBUGDIR"),
		Literals:      envBool("GOOVERLAY_LITERALS", false),
		Constants:     envBool("GOOVERLAY_CONSTANTS", true),
		MBA:           envBool("GOOVERLAY_MBA", true),
		ControlFlow:   envBool("GOOVERLAY_CONTROLFLOW", envBool("GOOVERLAY_EXPERIMENTAL_CONTROLFLOW", false)),
		Virtualize:    envBool("GOOVERLAY_VIRTUALIZE", false),
		Junk:          envBool("GOOVERLAY_JUNK", true),
		Opaque:        envBool("GOOVERLAY_OPAQUE", true),
		Tiny:          envBool("GOOVERLAY_TINY", false),
		StripComments: envBool("GOOVERLAY_STRIP_COMMENTS", true),
	}
}

func envBool(key string, defaultVal bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return defaultVal
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultVal
	}
}
