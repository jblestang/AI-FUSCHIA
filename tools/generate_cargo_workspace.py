#!/usr/bin/env python3
"""Generate Cargo.toml files for the standalone netstack3 fork."""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FIDL_STUB = """\
// Minimal stub of Fuchsia fuchsia.net FIDL types for standalone cargo builds.

#![allow(missing_docs)]

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Address { pub addr: [u8; 4] }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Address { pub addr: [u8; 16] }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IpAddress { Ipv4(Ipv4Address), Ipv6(Ipv6Address) }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Subnet { pub addr: IpAddress, pub prefix_len: u8 }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv4AddressWithPrefix { pub addr: Ipv4Address, pub prefix_len: u8 }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv6AddressWithPrefix { pub addr: Ipv6Address, pub prefix_len: u8 }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MacAddress { pub octets: [u8; 6] }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv4SocketAddress { pub address: Ipv4Address, pub port: u16 }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv6SocketAddress { pub address: Ipv6Address, pub port: u16, pub zone_index: u64 }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SocketAddress { Ipv4(Ipv4SocketAddress), Ipv6(Ipv6SocketAddress) }
"""

WORKSPACE_MEMBERS = [
    "libs/fidl-fuchsia-net-common",
    "libs/net-types-macros",
    "libs/net-types",
    "libs/net-declare-macros",
    "libs/net-declare",
    "libs/internet-checksum",
    "libs/explicit",
    "libs/diagnostics-traits",
    "libs/replace-with",
    "libs/packet",
    "libs/packet-formats",
    "libs/ip-test-macro",
    "libs/test_util",
    "libs/proptest-support",
    "netstack3/core/hashmap",
    "netstack3/core/lock-order",
    "netstack3/core/macros",
    "netstack3/core/teststd",
    "netstack3/core/sync",
    "netstack3/core/base",
    "netstack3/core/trace",
    "netstack3/core/filter",
    "netstack3/core/ip",
    "netstack3/core/device",
    "netstack3/core/datagram",
    "netstack3/core/tcp",
    "netstack3/core/udp",
    "netstack3/core/icmp_echo",
    "netstack3/core",
]

WORKSPACE_TOML = """\
[workspace]
resolver = "2"
members = [
{members}
]

[workspace.package]
edition = "2024"
license = "BSD-3-Clause"
version = "0.1.0"

[workspace.dependencies]
arc-swap = "1.7"
arrayvec = "0.7"
assert_matches = "1.5"
bitflags = "2.9"
byteorder = "1.5"
cfg-if = "1.0"
derivative = "2.2"
either = { version = "1.15", default-features = false }
digest = "0.10"
hmac = "0.12"
log = "0.4"
lru-cache = "0.1"
once_cell = "1.21"
proc-macro2 = "1.0"
quote = "1.0"
rand = "0.9"
rand_xorshift = "0.4"
ref-cast = "1.0"
siphasher = "1.0"
smallvec = { version = "1.15", features = ["const_generics"] }
sha2 = "0.10"
static_assertions = "1.1"
strum = { version = "0.26", default-features = false, features = ["derive"] }
strum_macros = "0.26"
syn = { version = "2.0", features = ["full", "visit-mut"] }
thiserror = "2.0"
zerocopy = { version = "0.8", features = ["derive"] }
"""


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def pkg(name: str, *, lib_name: str | None = None, proc_macro: bool = False) -> str:
    lines = [
        "[package]",
        f'name = "{name}"',
        "edition.workspace = true",
        "version.workspace = true",
        "license.workspace = true",
        "",
        "[lib]",
    ]
    if proc_macro:
        lines.append("proc-macro = true")
    if lib_name:
        lines.append(f'name = "{lib_name}"')
    return "\n".join(lines) + "\n"


def render(path: str, body: str) -> None:
    write(ROOT / path / "Cargo.toml", body)


def main() -> None:
    members = ",\n".join(f'    "{m}"' for m in WORKSPACE_MEMBERS)
    write(ROOT / "Cargo.toml", WORKSPACE_TOML.replace("{members}", members))

    write(ROOT / "libs/fidl-fuchsia-net-common/src/lib.rs", FIDL_STUB)
    render("libs/fidl-fuchsia-net-common", pkg("fidl-fuchsia-net-common"))

    for src, dst in [
        (ROOT / "libs/net-types/src/macros.rs", ROOT / "libs/net-types-macros/src/lib.rs"),
        (ROOT / "libs/net-declare/src/macros.rs", ROOT / "libs/net-declare-macros/src/lib.rs"),
    ]:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    render(
        "libs/net-types-macros",
        pkg("net-types-macros", proc_macro=True)
        + """
[dependencies]
assert_matches = { workspace = true }
proc-macro2 = { workspace = true }
quote = { workspace = true }
syn = { workspace = true }
""",
    )
    render(
        "libs/net-declare-macros",
        pkg("net-declare-macros", proc_macro=True)
        + """
[dependencies]
net_types = { package = "net-types", path = "../net-types" }
proc-macro2 = { workspace = true }
quote = { workspace = true }
syn = { workspace = true }
thiserror = { workspace = true }
""",
    )
    render(
        "libs/net-types",
        pkg("net-types")
        + """
[features]
default = ["std"]
std = []

[dependencies]
net_types_macros = { package = "net-types-macros", path = "../net-types-macros" }
zerocopy = { workspace = true, features = ["derive"] }
""",
    )
    render(
        "libs/net-declare",
        pkg("net-declare")
        + """
[dependencies]
fidl_fuchsia_net_common = { package = "fidl-fuchsia-net-common", path = "../fidl-fuchsia-net-common" }
net_declare_macros = { package = "net-declare-macros", path = "../net-declare-macros" }

[dev-dependencies]
net_types = { package = "net-types", path = "../net-types" }
""",
    )
    render("libs/internet-checksum", pkg("internet_checksum"))
    render("libs/explicit", pkg("explicit"))
    render(
        "libs/diagnostics-traits",
        pkg("diagnostics-traits")
        + """
[dependencies]
net_types = { package = "net-types", path = "../net-types" }
""",
    )
    render("libs/replace-with", pkg("replace-with", lib_name="replace_with"))
    render(
        "libs/packet",
        pkg("packet")
        + """
[dependencies]
arrayvec = { workspace = true }
replace_with = { package = "replace-with", path = "../replace-with" }
zerocopy = { workspace = true, features = ["derive"] }

[dev-dependencies]
assert_matches = { workspace = true }
test_util = { path = "../test_util" }
test-case = "3.3"
""",
    )
    render(
        "libs/packet-formats",
        pkg("packet_formats")
        + """
[dependencies]
byteorder = { workspace = true }
derivative = { workspace = true, features = ["use_core"] }
either = { workspace = true }
explicit = { path = "../explicit" }
internet_checksum = { path = "../internet-checksum" }
log = { workspace = true }
net_types = { package = "net-types", path = "../net-types" }
packet = { path = "../packet" }
thiserror = { workspace = true }
zerocopy = { workspace = true, features = ["derive"] }
""",
    )
    render(
        "libs/ip-test-macro",
        pkg("ip-test-macro", proc_macro=True)
        + """
[dependencies]
proc-macro2 = { workspace = true }
quote = { workspace = true }
syn = { workspace = true }
""",
    )
    render("libs/test_util", pkg("test_util"))
    render(
        "libs/proptest-support",
        pkg("proptest-support")
        + """
[dependencies]
proptest = "1.6"
""",
    )

    render("netstack3/core/hashmap", pkg("netstack3-hashmap", lib_name="netstack3_hashmap"))
    render("netstack3/core/lock-order", pkg("lock-order", lib_name="lock_order"))
    render(
        "netstack3/core/macros",
        pkg("netstack3-macros", proc_macro=True)
        + """
[dependencies]
proc-macro2 = { workspace = true }
quote = { workspace = true }
syn = { workspace = true }

[dev-dependencies]
assert_matches = { workspace = true }
net_types = { package = "net-types", path = "../../../libs/net-types" }
netstack3_base = { package = "netstack3-base", path = "../base", features = ["testutils", "instrumented"] }
""",
    )
    render("netstack3/core/teststd", pkg("teststd"))
    render(
        "netstack3/core/sync",
        pkg("netstack3-sync", lib_name="netstack3_sync")
        + """
[features]
instrumented = ["recursive-lock-panic", "rc-debug-names"]
recursive-lock-panic = []
rc-debug-names = []
testutils = ["instrumented"]
loom = ["rc-debug-names", "testutils", "dep:loom"]

[dependencies]
derivative = { workspace = true, features = ["use_core"] }
lock_order = { package = "lock-order", path = "../lock-order" }
loom = { version = "0.7", optional = true }
net_types = { package = "net-types", path = "../../../libs/net-types" }
""",
    )

    base = pkg("netstack3-base", lib_name="netstack3_base") + """
[features]
testutils = ["instrumented", "netstack3_sync/testutils", "dep:net_declare", "dep:teststd", "dep:assert_matches", "dep:rand_xorshift"]
instrumented = ["netstack3_sync/instrumented"]
benchmark = []

[dependencies]
arc-swap = { workspace = true }
arrayvec = { workspace = true }
assert_matches = { workspace = true, optional = true }
bitflags = { workspace = true }
derivative = { workspace = true, features = ["use_core"] }
diagnostics_traits = { package = "diagnostics-traits", path = "../../../libs/diagnostics-traits" }
either = { workspace = true }
explicit = { path = "../../../libs/explicit" }
log = { workspace = true }
net_declare = { package = "net-declare", path = "../../../libs/net-declare", optional = true }
net_types = { package = "net-types", path = "../../../libs/net-types" }
netstack3_hashmap = { package = "netstack3-hashmap", path = "../hashmap" }
netstack3_sync = { package = "netstack3-sync", path = "../sync" }
packet = { path = "../../../libs/packet" }
packet_formats = { package = "packet_formats", path = "../../../libs/packet-formats" }
rand = { workspace = true }
rand_xorshift = { workspace = true, optional = true }
smallvec = { workspace = true }
static_assertions = { workspace = true }
strum = { workspace = true }
strum_macros = { workspace = true }
teststd = { path = "../teststd", optional = true }
thiserror = { workspace = true }
zerocopy = { workspace = true, features = ["derive"] }
"""
    render("netstack3/core/base", base)

    stack_features = """
[features]
testutils = ["instrumented"]
instrumented = []
"""
    render(
        "netstack3/core/trace",
        pkg("netstack3-trace", lib_name="netstack3_trace") + stack_features + """
[dependencies]
netstack3_sync = { package = "netstack3-sync", path = "../sync" }
""",
    )
    render(
        "netstack3/core/filter",
        pkg("netstack3-filter", lib_name="netstack3_filter") + stack_features + """
[dependencies]
assert_matches = { workspace = true }
derivative = { workspace = true, features = ["use_core"] }
log = { workspace = true }
net_types = { package = "net-types", path = "../../../libs/net-types" }
netstack3_base = { package = "netstack3-base", path = "../base" }
netstack3_hashmap = { package = "netstack3-hashmap", path = "../hashmap" }
once_cell = { workspace = true }
packet = { path = "../../../libs/packet" }
packet_formats = { package = "packet_formats", path = "../../../libs/packet-formats" }
rand = { workspace = true }
replace_with = { package = "replace-with", path = "../../../libs/replace-with" }
zerocopy = { workspace = true, features = ["derive"] }
""",
    )
    render(
        "netstack3/core/ip",
        pkg("netstack3-ip", lib_name="netstack3_ip") + stack_features + """
[dependencies]
arrayvec = { workspace = true }
assert_matches = { workspace = true }
derivative = { workspace = true, features = ["use_core"] }
diagnostics_traits = { package = "diagnostics-traits", path = "../../../libs/diagnostics-traits" }
either = { workspace = true }
explicit = { path = "../../../libs/explicit" }
hmac = { workspace = true }
lock_order = { package = "lock-order", path = "../lock-order" }
log = { workspace = true }
lru-cache = { workspace = true }
net_declare = { package = "net-declare", path = "../../../libs/net-declare" }
net_types = { package = "net-types", path = "../../../libs/net-types" }
netstack3_base = { package = "netstack3-base", path = "../base" }
netstack3_filter = { package = "netstack3-filter", path = "../filter" }
netstack3_hashmap = { package = "netstack3-hashmap", path = "../hashmap" }
netstack3_macros = { package = "netstack3-macros", path = "../macros" }
netstack3_trace = { package = "netstack3-trace", path = "../trace" }
packet = { path = "../../../libs/packet" }
packet_formats = { package = "packet_formats", path = "../../../libs/packet-formats" }
rand = { workspace = true }
ref-cast = { workspace = true }
sha2 = { workspace = true }
static_assertions = { workspace = true }
thiserror = { workspace = true }
zerocopy = { workspace = true, features = ["derive"] }
""",
    )
    render(
        "netstack3/core/device",
        pkg("netstack3-device", lib_name="netstack3_device") + stack_features + """
[dependencies]
derivative = { workspace = true, features = ["use_core"] }
lock_order = { package = "lock-order", path = "../lock-order" }
log = { workspace = true }
net_types = { package = "net-types", path = "../../../libs/net-types" }
netstack3_base = { package = "netstack3-base", path = "../base" }
netstack3_filter = { package = "netstack3-filter", path = "../filter" }
netstack3_hashmap = { package = "netstack3-hashmap", path = "../hashmap" }
netstack3_ip = { package = "netstack3-ip", path = "../ip" }
netstack3_trace = { package = "netstack3-trace", path = "../trace" }
packet = { path = "../../../libs/packet" }
packet_formats = { package = "packet_formats", path = "../../../libs/packet-formats" }
ref-cast = { workspace = true }
""",
    )
    render(
        "netstack3/core/datagram",
        pkg("netstack3-datagram", lib_name="netstack3_datagram") + stack_features + """
[dependencies]
assert_matches = { workspace = true }
derivative = { workspace = true, features = ["use_core"] }
either = { workspace = true }
explicit = { path = "../../../libs/explicit" }
lock_order = { package = "lock-order", path = "../lock-order" }
net_types = { package = "net-types", path = "../../../libs/net-types" }
netstack3_base = { package = "netstack3-base", path = "../base" }
netstack3_filter = { package = "netstack3-filter", path = "../filter" }
netstack3_hashmap = { package = "netstack3-hashmap", path = "../hashmap" }
netstack3_ip = { package = "netstack3-ip", path = "../ip" }
packet = { path = "../../../libs/packet" }
packet_formats = { package = "packet_formats", path = "../../../libs/packet-formats" }
ref-cast = { workspace = true }
thiserror = { workspace = true }
""",
    )
    render(
        "netstack3/core/tcp",
        pkg("netstack3-tcp", lib_name="netstack3_tcp") + stack_features + """
[dependencies]
arrayvec = { workspace = true }
assert_matches = { workspace = true }
cfg-if = { workspace = true }
derivative = { workspace = true, features = ["use_core"] }
explicit = { path = "../../../libs/explicit" }
lock_order = { package = "lock-order", path = "../lock-order" }
log = { workspace = true }
net_types = { package = "net-types", path = "../../../libs/net-types" }
netstack3_base = { package = "netstack3-base", path = "../base" }
netstack3_filter = { package = "netstack3-filter", path = "../filter" }
netstack3_hashmap = { package = "netstack3-hashmap", path = "../hashmap" }
netstack3_ip = { package = "netstack3-ip", path = "../ip" }
netstack3_trace = { package = "netstack3-trace", path = "../trace" }
packet = { path = "../../../libs/packet" }
packet_formats = { package = "packet_formats", path = "../../../libs/packet-formats" }
rand = { workspace = true }
replace_with = { package = "replace-with", path = "../../../libs/replace-with" }
siphasher = { workspace = true }
smallvec = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
either = { workspace = true }
netstack3_macros = { package = "netstack3-macros", path = "../macros" }
""",
    )
    render(
        "netstack3/core/udp",
        pkg("netstack3-udp", lib_name="netstack3_udp") + stack_features + """
[dependencies]
derivative = { workspace = true, features = ["use_core"] }
either = { workspace = true }
lock_order = { package = "lock-order", path = "../lock-order" }
log = { workspace = true }
net_types = { package = "net-types", path = "../../../libs/net-types" }
netstack3_base = { package = "netstack3-base", path = "../base" }
netstack3_datagram = { package = "netstack3-datagram", path = "../datagram" }
netstack3_filter = { package = "netstack3-filter", path = "../filter" }
netstack3_hashmap = { package = "netstack3-hashmap", path = "../hashmap" }
netstack3_ip = { package = "netstack3-ip", path = "../ip" }
netstack3_trace = { package = "netstack3-trace", path = "../trace" }
packet = { path = "../../../libs/packet" }
packet_formats = { package = "packet_formats", path = "../../../libs/packet-formats" }
smallvec = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
netstack3_macros = { package = "netstack3-macros", path = "../macros" }
""",
    )
    render(
        "netstack3/core/icmp_echo",
        pkg("netstack3-icmp-echo", lib_name="netstack3_icmp_echo") + stack_features + """
[dependencies]
derivative = { workspace = true, features = ["use_core"] }
either = { workspace = true }
lock_order = { package = "lock-order", path = "../lock-order" }
log = { workspace = true }
net_types = { package = "net-types", path = "../../../libs/net-types" }
netstack3_base = { package = "netstack3-base", path = "../base" }
netstack3_datagram = { package = "netstack3-datagram", path = "../datagram" }
netstack3_ip = { package = "netstack3-ip", path = "../ip" }
packet = { path = "../../../libs/packet" }
packet_formats = { package = "packet_formats", path = "../../../libs/packet-formats" }
""",
    )
    render(
        "netstack3/core",
        pkg("netstack3-core", lib_name="netstack3_core")
        + """
[features]
instrumented = []
testutils = ["instrumented"]

[dependencies]
assert_matches = { workspace = true }
derivative = { workspace = true, features = ["use_core"] }
lock_order = { package = "lock-order", path = "lock-order" }
log = { workspace = true }
net_types = { package = "net-types", path = "../../libs/net-types" }
netstack3_base = { package = "netstack3-base", path = "base" }
netstack3_datagram = { package = "netstack3-datagram", path = "datagram" }
netstack3_device = { package = "netstack3-device", path = "device" }
netstack3_filter = { package = "netstack3-filter", path = "filter" }
netstack3_hashmap = { package = "netstack3-hashmap", path = "hashmap" }
netstack3_icmp_echo = { package = "netstack3-icmp-echo", path = "icmp_echo" }
netstack3_ip = { package = "netstack3-ip", path = "ip" }
netstack3_macros = { package = "netstack3-macros", path = "macros" }
netstack3_sync = { package = "netstack3-sync", path = "sync" }
netstack3_tcp = { package = "netstack3-tcp", path = "tcp" }
netstack3_trace = { package = "netstack3-trace", path = "trace" }
netstack3_udp = { package = "netstack3-udp", path = "udp" }
packet = { path = "../../libs/packet" }
packet_formats = { package = "packet_formats", path = "../../libs/packet-formats" }
zerocopy = { workspace = true, features = ["derive"] }
""",
    )

    print(f"Generated workspace with {len(WORKSPACE_MEMBERS)} members under {ROOT}")


if __name__ == "__main__":
    main()
