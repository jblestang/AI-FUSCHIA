// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! IPS state including RFC 5722 fragment assembly caches.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::ops::Range;

use net_types::ip::{Ip, IpAddr, IpVersionMarker, Ipv4, Ipv6};
use netstack3_hashmap::hash_map::{Entry, HashMap};
use packet::Buf;
use packet_formats::ip::IpProto;

use crate::tcp_flow::{TcpFlowDirection, TcpFlowKey, TcpFlowState, IpsTcpFlowTable};
use crate::view::{FragmentEvent, IpFragmentInfo, IpFragmentMetadata, ReceivedTcpSegmentView, ReassemblyOutcome};

/// IPS layer state.
#[derive(Debug)]
pub struct IpsState {
    pub(crate) ipv4: IpsFragmentCache<Ipv4>,
    pub(crate) ipv6: IpsFragmentCache<Ipv6>,
    /// TCP flow state for sequence/ACK mangling.
    tcp_flows: RefCell<IpsTcpFlowTable>,
    /// L7 handlers that returned [`crate::IpsReceiveError::QueueFull`].
    l7_queue_full_drops: Cell<u64>,
    /// When true, IPS ingress is delivered via the zero-copy path.
    pub enabled: bool,
}

impl IpsState {
    /// Creates empty IPS state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of L7 deliveries rejected with [`crate::IpsReceiveError::QueueFull`].
    pub fn l7_queue_full_drops(&self) -> u64 {
        self.l7_queue_full_drops.get()
    }

    pub(crate) fn record_l7_queue_full(&self) {
        self.l7_queue_full_drops.set(self.l7_queue_full_drops.get().saturating_add(1));
    }

    /// Looks up or inserts per-flow TCP state for `view` and runs `f` with the
    /// flow and stream direction. Used by L7 handlers during inline TCP editing.
    pub fn with_tcp_flow_for_segment<R>(
        &self,
        view: &ReceivedTcpSegmentView,
        f: impl FnOnce(&mut TcpFlowState, TcpFlowDirection) -> R,
    ) -> Option<R> {
        let hdr = view.tcp_header()?;
        let (src, dst) = view.addrs();
        let (key, src_is_client) =
            TcpFlowKey::from_endpoints(src, hdr.src_port, dst, hdr.dst_port);
        let direction = if src_is_client {
            TcpFlowDirection::ClientToServer
        } else {
            TcpFlowDirection::ServerToClient
        };
        let mut flows = self.tcp_flows.borrow_mut();
        let flow = flows.get_or_insert(key);
        Some(f(flow, direction))
    }

    /// Returns the number of flows currently tracked in the TCP flow table.
    pub fn tcp_flow_count(&self) -> usize {
        self.tcp_flows.borrow().len()
    }

    /// Looks up flow state for `view` and runs `f` with a [`TcpOverwriter`].
    pub fn with_tcp_overwriter<R>(
        &self,
        view: &mut ReceivedTcpSegmentView,
        f: impl FnOnce(crate::tcp_overwrite::TcpOverwriter<'_>) -> R,
    ) -> Option<R> {
        let hdr = view.tcp_header()?;
        let (src, dst) = view.addrs();
        let (key, src_is_client) =
            TcpFlowKey::from_endpoints(src, hdr.src_port, dst, hdr.dst_port);
        let direction = if src_is_client {
            TcpFlowDirection::ClientToServer
        } else {
            TcpFlowDirection::ServerToClient
        };
        let mut flows = self.tcp_flows.borrow_mut();
        let flow = flows.get_or_insert(key);
        Some(f(view.tcp_overwriter(flow, direction)))
    }
}

impl Default for IpsState {
    fn default() -> Self {
        Self {
            ipv4: IpsFragmentCache::new(),
            ipv6: IpsFragmentCache::new(),
            tcp_flows: RefCell::new(IpsTcpFlowTable::new()),
            l7_queue_full_drops: Cell::new(0),
            enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;

    use net_types::ip::Ipv4Addr;
    use netstack3_base::NetworkSerializationContext;
    use packet::{Buf, NestableSerializer as _, Serializer};
    use packet_formats::ethernet::{EtherType, EthernetFrameBuilder};
    use packet_formats::ip::{IpProto, Ipv4Proto};
    use packet_formats::tcp::TcpSegmentBuilder;

    use alloc::vec;

    use super::*;
    use crate::view::{IpFragmentInfo, IpFragmentMetadata};

    const LOCAL: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
    const REMOTE: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);
    const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(100).unwrap();
    const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(200).unwrap();

    fn tcp_view(src_is_client: bool) -> ReceivedTcpSegmentView {
        let (ip_src, ip_dst, tcp_src, tcp_dst) = if src_is_client {
            (REMOTE, LOCAL, REMOTE_PORT, LOCAL_PORT)
        } else {
            (LOCAL, REMOTE, LOCAL_PORT, REMOTE_PORT)
        };
        let tcp = TcpSegmentBuilder::new(ip_src, ip_dst, tcp_src, tcp_dst, 1000, None, 65535);
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            ip_src,
            ip_dst,
            64,
            Ipv4Proto::Proto(IpProto::Tcp),
        );
        let eth = EthernetFrameBuilder::new(
            net_types::ethernet::Mac::new([0x02; 6]),
            net_types::ethernet::Mac::new([0x03; 6]),
            EtherType::Ipv4,
            0,
        );
        let frame = Buf::new(vec![0xAA; 8], ..)
            .wrap_in(tcp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        let ip_offset = packet_formats::ethernet::ETHERNET_HDR_LEN_NO_TAG;
        let body_start = ip_offset + packet_formats::ipv4::HDR_PREFIX_LEN;
        let frame_len = frame.len();
        let tcp_hdr = crate::view::parse_tcp_header(&frame, 0, body_start).unwrap();
        let payload_start = tcp_hdr.header_range.end;
        ReceivedTcpSegmentView::new(
            alloc::vec![Buf::new(frame, ..)],
            alloc::vec![IpFragmentInfo {
                eth_frame_index: 0,
                ip_packet_range: ip_offset..frame_len,
                identification: 1,
                fragment_offset: 0,
                more_fragments: false,
                ip_body_range: body_start..frame_len,
            }],
            IpFragmentMetadata {
                reassembly_outcome: ReassemblyOutcome::NotApplicable,
                ..Default::default()
            },
            Some(tcp_hdr),
            alloc::vec![(0, payload_start..frame_len)],
            if src_is_client { LOCAL.into() } else { REMOTE.into() },
            if src_is_client { REMOTE.into() } else { LOCAL.into() },
        )
    }

    #[test]
    fn tcp_flow_table_shared_across_directions() {
        use crate::tcp_overwrite::TcpPayloadEdit;

        let state = IpsState::new();
        let mut client_view = tcp_view(true);
        state
            .with_tcp_overwriter(&mut client_view, |mut overwriter| {
                overwriter
                    .apply_edit(TcpPayloadEdit { keep_len: 4 })
                    .expect("client edit");
            })
            .expect("client segment");
        assert_eq!(state.tcp_flow_count(), 1);

        let mut server_view = tcp_view(false);
        state
            .with_tcp_overwriter(&mut server_view, |mut overwriter| {
                overwriter.prepare_inbound().expect("server segment");
            })
            .expect("server ack");
        assert_eq!(state.tcp_flow_count(), 1, "both directions share one flow key");
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
