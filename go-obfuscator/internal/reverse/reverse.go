package reverse

import (
	"sort"
	"strings"

	"github.com/ai-fuchsia/go-obfuscator/internal/mapfile"
)

// Text replaces obfuscated identifiers in text using a map file (longest match first).
func Text(mapPath, input string) (string, error) {
	f, err := mapfile.Read(mapPath)
	if err != nil {
		return "", err
	}
	if len(f.Entries) == 0 {
		return input, nil
	}

	type pair struct{ from, to string }
	pairs := make([]pair, 0, len(f.Entries))
	for _, e := range f.Entries {
		pairs = append(pairs, pair{from: e.Obfuscated, to: e.Original})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].from) > len(pairs[j].from)
	})

	out := input
	for _, p := range pairs {
		out = strings.ReplaceAll(out, p.from, p.to)
	}
	return out, nil
}
