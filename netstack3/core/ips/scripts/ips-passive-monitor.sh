#!/usr/bin/env bash
# Copyright 2026 The Fuchsia Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Passive IPS monitor: read-only copy of traffic on a Linux interface.
#
# This script does NOT insert iptables/NFQUEUE rules, does NOT bridge traffic,
# and does NOT forward packets. It only receives a copy of frames (typically from
# a switch SPAN/mirror port or a dedicated sniff NIC) and runs them through the
# netstack3 IPS ingress path for flow analysis.
#
# Usage:
#   sudo ./netstack3/core/ips/scripts/ips-passive-monitor.sh eth1
#   sudo ./netstack3/core/ips/scripts/ips-passive-monitor.sh eth1 --verbose
#
# Recommended topology (copy-only, no inline modification):
#
#   [live network] ----(in-path)----> router/host eth0  (untouched by this IDS)
#                         |
#                    SPAN / mirror
#                         v
#                   IDS host eth1  <-- bind passive_capture here (no IP required)
#
# Requirements:
#   - Linux with AF_PACKET
#   - CAP_NET_RAW or root (for raw socket bind)
#   - Capture interface should NOT be the default route / production path

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
IFACE="${1:-}"
shift || true

if [[ -z "${IFACE}" ]]; then
  echo "Usage: sudo $0 IFACE [--verbose] [--promisc] [--build-only]" >&2
  echo "  IFACE     Mirror/SPAN or dedicated sniff interface (not the live path)" >&2
  exit 2
fi

VERBOSE=()
PROMISC=()
BUILD_ONLY=0
for arg in "$@"; do
  case "${arg}" in
    --verbose|-v) VERBOSE+=(--verbose) ;;
    --promisc) PROMISC+=(--promisc) ;;
    --build-only) BUILD_ONLY=1 ;;
    *)
      echo "Unknown option: ${arg}" >&2
      exit 2
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "error: root or CAP_NET_RAW is required for AF_PACKET capture" >&2
  echo "  Run: sudo $0 ${IFACE}" >&2
  exit 1
fi

if ! ip link show "${IFACE}" >/dev/null 2>&1; then
  echo "error: interface ${IFACE} does not exist" >&2
  exit 1
fi

if ip route show default 2>/dev/null | grep -q "dev ${IFACE}"; then
  echo "warning: ${IFACE} is the default route interface." >&2
  echo "         For passive copy-only IDS, prefer a SPAN/mirror port without a default route." >&2
fi

if ip -4 addr show dev "${IFACE}" 2>/dev/null | grep -q "inet "; then
  echo "warning: ${IFACE} has an IPv4 address configured." >&2
  echo "         Mirror/sniff ports are usually address-less; live traffic is unaffected but verify topology." >&2
fi

# Bring link up so the NIC receives mirrored frames; we do not add routes or iptables rules.
ip link set "${IFACE}" up

echo "Starting passive IPS capture on ${IFACE} (read-only, no transmit path configured)."
echo "Live traffic on other interfaces is not modified by this tool."

cd "${REPO_ROOT}"

cargo build -p netstack3-ips --features testutils --example passive_capture --release

if [[ "${BUILD_ONLY}" -eq 1 ]]; then
  echo "Build complete (--build-only)."
  exit 0
fi

exec "${REPO_ROOT}/target/release/examples/passive_capture" \
  --interface "${IFACE}" \
  "${PROMISC[@]}" \
  "${VERBOSE[@]}"
