// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! IPS state including RFC 5722 fragment assembly caches.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ops::Range;

use net_types::ip::{Ip, IpAddr, IpVersionMarker, Ipv4, Ipv6};
use netstack3_hashmap::hash_map::{Entry, HashMap};
use packet::Buf;
use packet_formats::ip::IpProto;

use crate::view::{FragmentEvent, IpFragmentInfo, IpFragmentMetadata, ReassemblyOutcome};
use crate::tcp_flow::IpsTcpFlowTable;

/// IPS layer state.
#[derive(Debug)]
pub struct IpsState {
    pub(crate) ipv4: IpsFragmentCache<Ipv4>,
    pub(crate) ipv6: IpsFragmentCache<Ipv6>,
    /// TCP flow state for sequence/ACK mangling.
    pub tcp_flows: IpsTcpFlowTable,
    /// When true, IPS ingress is delivered via the zero-copy path.
    pub enabled: bool,
}

impl IpsState {
    /// Creates empty IPS state.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for IpsState {
    fn default() -> Self {
        Self {
            ipv4: IpsFragmentCache::new(),
            ipv6: IpsFragmentCache::new(),
            tcp_flows: IpsTcpFlowTable::new(),
            enabled: false,
        }
    }
}

/// Stored fragment data referencing driver-owned memory (zero-copy).
#[derive(Debug)]
pub(crate) struct StoredFragment {
    pub eth_frame: Buf<Vec<u8>>,
    /// Byte range of the IP packet within `eth_frame`.
    pub ip_packet_range: Range<usize>,
    pub identification: u32,
    /// Fragment offset in 8-octet units.
    pub fragment_offset: u16,
    pub more_fragments: bool,
    /// Byte range of the IP body within `eth_frame`.
    pub ip_body_range: Range<usize>,
}

/// In-progress or completed assembly for one datagram.
#[derive(Debug)]
pub(crate) struct DatagramAssembly<I: Ip> {
    pub src_ip: I::Addr,
    pub dst_ip: I::Addr,
    pub identification: u32,
    pub fragments: Vec<StoredFragment>,
    pub events: Vec<FragmentEvent>,
    pub missing_blocks: BTreeSet<BlockRange>,
    pub aborted: bool,
}

/// Inclusive fragment block range in 8-octet units (matches stack reassembly).
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) struct BlockRange {
    pub start: u16,
    pub end: u16,
}

/// Maximum fragment blocks (13-bit offset field).
pub(crate) const MAX_FRAGMENT_BLOCKS: u16 = (1 << 13) - 1;

/// Fragment block size for IPv4 and IPv6.
pub(crate) const FRAGMENT_BLOCK_SIZE: usize = 8;

/// Key for fragment assembly cache.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct AssemblyKey<I: Ip> {
    pub src_ip: I::Addr,
    pub dst_ip: I::Addr,
    pub identification: u32,
    pub proto: IpProto,
    _ip: IpVersionMarker<I>,
}

impl<I: Ip> AssemblyKey<I> {
    pub fn new(src_ip: I::Addr, dst_ip: I::Addr, identification: u32, proto: IpProto) -> Self {
        Self { src_ip, dst_ip, identification, proto, _ip: IpVersionMarker::new() }
    }
}

/// Result of feeding one fragment into the assembly cache.
#[derive(Debug)]
pub(crate) enum AssemblyProgress<I: Ip> {
    /// Waiting for more fragments.
    NeedMore,
    /// Assembly complete; ready for L7 delivery.
    Ready(DatagramAssembly<I>),
    /// RFC 5722 overlap abort; deliver metadata to L7 without payload.
    Aborted(DatagramAssembly<I>),
}

/// Per-IP-version fragment cache with RFC 5722 overlap handling.
#[derive(Debug)]
pub struct IpsFragmentCache<I: Ip> {
    assemblies: RefCell<HashMap<AssemblyKey<I>, DatagramAssembly<I>>>,
}

impl<I: Ip> IpsFragmentCache<I> {
    /// Creates an empty cache.
    pub fn new() -> Self {
        Self { assemblies: RefCell::new(HashMap::new()) }
    }

    pub(crate) fn assemblies(&self) -> &RefCell<HashMap<AssemblyKey<I>, DatagramAssembly<I>>> {
        &self.assemblies
    }
}

/// Builds [`IpFragmentMetadata`] from an assembly.
pub(crate) fn assembly_metadata<I: Ip>(
    assembly: &DatagramAssembly<I>,
    outcome: ReassemblyOutcome,
) -> IpFragmentMetadata {
    IpFragmentMetadata {
        fragments: assembly
            .fragments
            .iter()
            .enumerate()
            .map(|(i, f)| IpFragmentInfo {
                eth_frame_index: i,
                ip_packet_range: f.ip_packet_range.clone(),
                identification: f.identification,
                fragment_offset: f.fragment_offset,
                more_fragments: f.more_fragments,
                ip_body_range: f.ip_body_range.clone(),
            })
            .collect(),
        events: assembly.events.clone(),
        reassembly_outcome: outcome,
    }
}

/// Maps IP addresses to the unified [`IpAddr`] type.
pub(crate) fn ip_addr_v4(src: net_types::ip::Ipv4Addr, dst: net_types::ip::Ipv4Addr) -> (IpAddr, IpAddr) {
    (IpAddr::V4(src), IpAddr::V4(dst))
}

pub(crate) fn ip_addr_v6(src: net_types::ip::Ipv6Addr, dst: net_types::ip::Ipv6Addr) -> (IpAddr, IpAddr) {
    (IpAddr::V6(src), IpAddr::V6(dst))
}
