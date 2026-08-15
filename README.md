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

# Build the Linux L2 bridge host (TAP + netstack3; lives in core integration test)
cargo test -p netstack3-core --test linux_bridge_host --features testutils --no-run
```

## Linux L2 bridge host

Attaches netstack3 to a TAP interface enslaved to a Linux bridge. Implemented as a
`netstack3-core` integration test so it reuses `FakeBindingsCtx` with minimal core
changes (testutils feature wiring + one `[[test]]` entry).

```bash
# Create bridge + TAP (as root)
ip link add name br0 type bridge
ip tuntap add dev tap0 mode tap
ip link set tap0 master br0
ip link set tap0 address 00:01:02:03:04:05 up
ip link set br0 up

# Run UDP self-test (no TAP)
cargo test -p netstack3-core --test linux_bridge_host --features testutils -- --self-test

# Run on TAP (needs /dev/net/tun); listens on UDP 4242 by default
cargo test -p netstack3-core --test linux_bridge_host --features testutils -- tap0

# Send a datagram from another host on the bridge:
echo -n hello | nc -u 192.0.2.1 4242
```

Default stack: `192.0.2.1/24`, MAC `00:01:02:03:04:05` (TEST_ADDRS). Default UDP port: **4242**.

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
