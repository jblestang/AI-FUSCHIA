# IPS libFuzzer targets

Fuzz tests for the PR #12 UDP zero-copy receive path (and TCP ingress on later branches).

## Targets

| Target | Entry point | Purpose |
|--------|-------------|---------|
| `process_ethernet_frame` | `netstack3_ips::process_ethernet_frame` | Ethernet-level ingress; must not panic on arbitrary bytes |
| `add_fragment` | `netstack3_ips::fragment::add_fragment` | RFC 5722 assembly cache; must not panic on synthetic fragments |

## Running

Requires **nightly** Rust and a C++ toolchain (`build-essential`):

```bash
cd netstack3/core/ips/fuzz
cargo +nightly fuzz run process_ethernet_frame -- -max_total_time=30
cargo +nightly fuzz run add_fragment -- -max_total_time=30
```

## CI-friendly property tests

`cargo test -p netstack3-ips` also runs `process_ethernet_frame_never_panics` (proptest) in `receive.rs`, which exercises the same entry point without libFuzzer.
