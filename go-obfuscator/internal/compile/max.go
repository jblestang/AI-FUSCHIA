package compile

// ApplyMaxDefaults turns on every obfuscation and security pass.
func ApplyMaxDefaults(cfg *Config) {
	cfg.Literals = true
	cfg.Constants = true
	cfg.MBA = true
	cfg.ControlFlow = true
	cfg.Virtualize = true
	cfg.Junk = true
	cfg.Opaque = true
	cfg.Tamper = true
	cfg.AntiDebug = true
	cfg.AntiEmulation = true
	cfg.Max = true
}

// applyMaxOverride enables all passes for a directive override.
func applyMaxOverride(o *PassOverride) {
	o.Literals = boolPtr(true)
	o.Constants = boolPtr(true)
	o.MBA = boolPtr(true)
	o.ControlFlow = boolPtr(true)
	o.Virtualize = boolPtr(true)
	o.Junk = boolPtr(true)
	o.Opaque = boolPtr(true)
	o.Tamper = boolPtr(true)
	o.AntiDebug = boolPtr(true)
	o.AntiEmulation = boolPtr(true)
	o.Multipath = boolPtr(true)
}

func boolPtr(v bool) *bool {
	return &v
}

func guardDecoyCountFor(cfg Config) int {
	if cfg.Max {
		return 8
	}
	return 4
}