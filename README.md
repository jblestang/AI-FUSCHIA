# AI-FUSCHIA

A standalone fork of [Fuchsia netstack3](https://fuchsia.dev/fuchsia-src/contribute/contributing-to-netstack/netstack3), extracted from Google's Fuchsia project and wired up for plain `cargo` builds.

## Overview

Netstack3 is Fuchsia's Rust networking stack. Roughly 90% of the code lives in the platform-agnostic **core** crate tree under `netstack3/core/`. This repository vendors that core plus the connectivity libraries it depends on, so you can develop and compile without the Fuchsia `fx` build system.

## Requirements

- Rust **1.85+** (edition 2024). A `rust-toolchain.toml` pins stable.
- Standard Linux/macOS host toolchain (`x86_64-unknown-linux-gnu` tested).

## Quick start

```bash
# Regenerate Cargo.toml files after changing dependency layout
python3 tools/generate_cargo_workspace.py

# Check the platform-agnostic core library
cargo check -p netstack3-core

# Check the entire workspace
cargo check --workspace
```

## Layout

```
netstack3/core/     # netstack3 core crates (base, ip, tcp, udp, device, …)
libs/               # Vendored Fuchsia connectivity libraries (net-types, packet-formats, …)
tools/              # Workspace generator and import helpers
```

## Fuchsia bindings

The Fuchsia-specific **bindings** crate (FIDL, inspect, component runner) is not included yet. This fork targets the platform-agnostic core that Fuchsia upstream also develops with `cargo`.

## Upstream

Source is imported from [fuchsia.googlesource.com/fuchsia](https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/src/connectivity/network/netstack3). See individual file headers for copyright and license (BSD-style).

## Notes

- A minimal `fidl-fuchsia-net-common` stub crate satisfies `net-declare` FIDL macro dependencies on host builds.
- Some crates.io dependency versions differ slightly from Fuchsia's patched third-party crates (e.g. `rand 0.9`, `smallvec` with `const_generics`).
