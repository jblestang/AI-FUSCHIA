# Passive Linux IDS capture

Read-only IPS monitoring on a Linux interface using **AF_PACKET** (no transmit, no inline modification).

## Topology (copy-only)

```
[live network] ---- eth0 (production path, untouched)
                      |
                 SPAN / mirror
                      v
                 eth1 (IDS capture NIC — no IP required)
```

Do **not** bind this tool to the default-route interface or use NFQUEUE/iptables inline modes if you need a passive copy.

## Quick start

```bash
# Mirror traffic to eth1 on the IDS host, then:
sudo ./netstack3/core/ips/scripts/ips-passive-monitor.sh eth1

# Build only (no capture):
sudo ./netstack3/core/ips/scripts/ips-passive-monitor.sh eth1 --build-only
```

## Options

| Flag | Description |
|------|-------------|
| `--promisc` | Join interface promiscuous multicast (usually unnecessary on SPAN ports) |
| `--build-only` | Compile the example and exit |

Rejected frames (malformed Ethernet, non-IP, non-UDP/TCP, truncated) are printed to stdout; accepted flows are counted silently until Ctrl+C summary.

## Manual run

```bash
sudo cargo run -p netstack3-ips --example passive_capture -- \
  --interface eth1
```

## What it does

1. Opens `AF_PACKET` `SOCK_RAW` bound to the capture interface (**recv only**)
2. Feeds each Ethernet frame to `process_ethernet_frame`
3. **Logs only rejected frames** (length, EtherType, hex prefix)
4. Prints capture statistics on Ctrl+C

## Requirements

- Linux with `CAP_NET_RAW` or root
- Rust toolchain (builds `passive_capture` example)
- Dedicated mirror/sniff interface recommended

## What it does **not** do

- No packet transmission on the capture interface
- No iptables/NFQUEUE inline hook
- No bridging or IP forwarding changes
- No modification of the live production stream (when using SPAN/mirror)
