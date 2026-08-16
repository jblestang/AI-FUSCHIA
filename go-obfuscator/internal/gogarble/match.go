package gogarble

import (
	"path"
	"strings"
)

// Match reports whether importPath matches any comma-separated glob pattern.
// Patterns follow GOGARBLE / GOPRIVATE style: prefix match, or glob with * and ?.
func Match(importPath, patterns string) bool {
	if patterns == "" || importPath == "" {
		return false
	}
	for _, pattern := range strings.Split(patterns, ",") {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if matchPattern(importPath, pattern) {
			return true
		}
	}
	return false
}

func matchPattern(importPath, pattern string) bool {
	if strings.ContainsAny(pattern, "*?[") {
		ok, _ := path.Match(pattern, importPath)
		if ok {
			return true
		}
		// Also try prefix before first wildcard as module root.
		if i := strings.IndexAny(pattern, "*?["); i > 0 {
			prefix := strings.TrimSuffix(pattern[:i], "/")
			if prefix != "" && strings.HasPrefix(importPath, prefix) {
				return true
			}
		}
		return false
	}
	if importPath == pattern {
		return true
	}
	return strings.HasPrefix(importPath, pattern+"/") || strings.HasPrefix(importPath, pattern)
}
