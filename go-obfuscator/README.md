# gooverlay — Garble-style Go obfuscator overlay

Prototype d'obfuscateur Go qui s'appuie sur le **compilateur officiel** via `-toolexec`, avec une API et des passes inspirées de [Garble](https://github.com/burrowers/garble).

## Fonctionnalités

| Technique | Garble | gooverlay |
|-----------|--------|-----------|
| Renommage identifiants non exportés | ✅ | ✅ |
| `-literals` (opt-in) | ✅ | ✅ |
| `-seed` / `-seed=random` | ✅ | ✅ |
| `-tiny` (best-effort) | ✅ | ✅ (partiel, sans patch linker) |
| `-trimpath` + chemins hashés | ✅ | ✅ |
| `GOGARBLE` glob scoping | ✅ | ✅ |
| `reverse` / map de noms | ✅ | ✅ |
| `build` / `test` / `run` | ✅ | ✅ |
| Stripping symboles / DWARF | ✅ | ✅ |
| Constantes + MBA + CF | partiel | ✅ (extras) |
| Code virtualization (`-virtualize`) | — | ✅ (simple `int` returns) |
| Renommage exports / SSA CF | partiel | ❌ (future) |

## Installation

```bash
cd go-obfuscator
go install ./cmd/gooverlay
```

## Usage (style Garble)

```bash
# Build obfusqué avec littéraux (comme garble -literals)
gooverlay build -literals -o /tmp/example-obf ./example

# Seed déterministe
gooverlay build -literals -seed=my-secret -o /tmp/example-obf ./example

# Seed aléatoire (affiché sur stderr)
gooverlay build -literals -seed=random -o /tmp/example-obf ./example

# Mode tiny + debug
gooverlay build -literals -tiny -debug -o /tmp/example-obf ./example

# Code virtualization (simple int functions → bytecode VM)
gooverlay build -literals -virtualize -o /tmp/example-obf ./example

# Limiter le scope (comme GOGARBLE)
GOGARBLE='github.com/my/module/*' gooverlay build -literals ./...

# Désobfusquer une stack trace
gooverlay reverse panic.txt

# Afficher la table de noms
gooverlay map

# Tests obfusqués
gooverlay test -literals ./...

# Vérification
./scripts/check.sh
```

## Architecture

```
gooverlay build ./pkg
       │
       ▼
go build -toolexec=gooverlay -trimpath ./pkg
       │
       ├── compile → rename → virtualize → strip comments → literals → constants → MBA
       │             → junk → opaque predicates → control-flow → compile
       └── link → -s -w -buildid= [tiny extras]
```

## Variables d'environnement

| Variable | Description |
|----------|-------------|
| `GOGARBLE` / `GOOVERLAY` | Glob de packages à obfusquer |
| `GOOVERLAY_SEED` | Seed déterministe |
| `GOOVERLAY_MAPFILE` | Fichier JSON pour `reverse` / `map` |
| `GOOVERLAY_DEBUGDIR` | Répertoire de sources obfusquées (`-debug`) |
| `GOOVERLAY_LITERALS` | `1`/`0` — littéraux string |
| `GOOVERLAY_CONSTANTS` | Constantes numériques (défaut `1`) |
| `GOOVERLAY_MBA` | MBA (défaut `1`) |
| `GOOVERLAY_CONTROLFLOW` | CF flattening (défaut `0`, expérimental) |
| `GOOVERLAY_VIRTUALIZE` | Bytecode VM (`-virtualize`) |

## Annotations (`//gooverlay:`)

Directives live in **AST doc comments** (parsed with `parser.ParseComments`), like Garble's `//garble:controlflow`. They are read before transforms and stripped from output.

```go
//gooverlay:file literals          // file-level defaults (package comment)

//gooverlay:virtualize              // enable VM for this function
func applySalt(n int) int { ... }

//gooverlay:off                     // skip all passes for this function
func debugHelper() { ... }

//gooverlay:literals no-mba          // enable literals, disable MBA
func mixed() { ... }
```

| Directive | Effect |
|-----------|--------|
| `//gooverlay:pass` | Force-enable pass (`literals`, `virtualize`, `controlflow`, …) |
| `//gooverlay:no-pass` | Force-disable pass |
| `//gooverlay:off` / `skip` / `plain` | Skip all obfuscation for that function |
| `//gooverlay:file …` | File-level defaults (in package comment) |

Per-function settings override file defaults; both override global CLI/env when explicit.

## Limites vs Garble production

- Pas de patch linker → `-tiny` ne supprime pas les panics runtime comme Garble
- Pas de renommage de chemins d'import inter-packages
- Control-flow moins avancé que le SSA de Garble
- Exports toujours préservés (comme Garble aujourd'hui)
- cgo / plugins non testés

## Références

- [Garble](https://github.com/burrowers/garble)
- [Go build -toolexec](https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies)
