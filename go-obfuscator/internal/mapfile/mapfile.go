package mapfile

import (
	"encoding/json"
	"os"
	"sync"
)

// Entry records one obfuscation mapping.
type Entry struct {
	Pkg        string `json:"pkg"`
	Kind       string `json:"kind"`
	Original   string `json:"original"`
	Obfuscated string `json:"obfuscated"`
}

// File holds reversible mappings for a build.
type File struct {
	Seed    string  `json:"seed"`
	Entries []Entry `json:"entries"`
}

var mu sync.Mutex

// Record appends a mapping if path is set and obfuscated != original.
func Record(path, seed, pkg, kind, original, obfuscated string) error {
	if path == "" || original == "" || obfuscated == "" || original == obfuscated {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()

	f, err := load(path)
	if err != nil {
		return err
	}
	if f.Seed == "" {
		f.Seed = seed
	}
	for _, e := range f.Entries {
		if e.Pkg == pkg && e.Kind == kind && e.Original == original {
			return nil
		}
	}
	f.Entries = append(f.Entries, Entry{
		Pkg: pkg, Kind: kind, Original: original, Obfuscated: obfuscated,
	})
	return save(path, f)
}

func load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{}, nil
		}
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return &File{}, nil
	}
	return &f, nil
}

func save(path string, f *File) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Read loads a map file from disk.
func Read(path string) (*File, error) {
	mu.Lock()
	defer mu.Unlock()
	return load(path)
}
