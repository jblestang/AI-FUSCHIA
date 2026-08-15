// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Multi-layer zero-copy views delivered to Layer 7 IPS analysis.

use alloc::vec::Vec;
use core::ops::Range;

use net_types::ip::{IpAddr, Ipv4Addr, Ipv6Addr};
use packet::{Buf, FragmentedByteSlice};

use crate::frame_store::EthFrameStore;

/// Metadata describing IP fragment reception and reassembly per RFC 5722.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFragmentMetadata {
    /// Per-fragment information retained for analysis.
    pub fragments: Vec<IpFragmentInfo>,
    /// Anomalies detected while processing fragments.
    pub events: Vec<FragmentEvent>,
    /// Outcome of IP-layer reassembly.
    pub reassembly_outcome: ReassemblyOutcome,
}

impl Default for IpFragmentMetadata {
    fn default() -> Self {
        Self {
            fragments: Vec::new(),
            events: Vec::new(),
            reassembly_outcome: ReassemblyOutcome::NotApplicable,
        }
    }
}

/// Information about one received IP fragment and its backing Ethernet frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFragmentInfo {
    /// Index into [`ReceivedUdpDatagramView::eth_frames`].
    pub eth_frame_index: usize,
    /// Byte range of the IP packet within the Ethernet frame buffer.
    pub ip_packet_range: Range<usize>,
    /// Fragment identification field.
    pub identification: u32,
    /// Fragment offset in 8-octet units.
    pub fragment_offset: u16,
    /// More-fragments flag.
    pub more_fragments: bool,
    /// Byte range of the IP payload body within the Ethernet frame buffer.
    pub ip_body_range: Range<usize>,
}

/// An IP fragment processing event surfaced for IPS analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentEvent {
    /// A fragment overlapped a previously received fragment (RFC 5722).
    OverlappingFragment {
        identification: u32,
        fragment_offset: u16,
        conflicting_fragment_index: usize,
    },
    /// An exact duplicate fragment was received and dropped (RFC 5722).
    DuplicateFragment { identification: u32, fragment_offset: u16 },
}

/// Outcome of IP fragment reassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyOutcome {
    /// The datagram was not fragmented.
    NotApplicable,
    /// Reassembly is still in progress; no L7 delivery yet.
    Incomplete,
    /// All fragments received and reassembly completed successfully.
    Complete,
    /// Reassembly aborted due to RFC 5722 overlap policy.
    AbortedRfc5722Overlap,
}

/// Parsed UDP header fields and their location within a stored frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeaderView {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    /// Index into [`ReceivedUdpDatagramView::eth_frames`].
    pub eth_frame_index: usize,
    /// Byte range of the 8-byte UDP header within the frame buffer.
    pub header_range: Range<usize>,
}

/// A byte range referencing UDP payload bytes inside a stored frame buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PayloadPart {
    eth_frame_index: usize,
    range: Range<usize>,
}

/// Zero-copy multi-layer view of a received UDP datagram for IPS analysis.
///
/// All accessors return views into the underlying driver-owned frame buffers
/// stored in [`ReceivedUdpDatagramView::eth_frames`]. No payload bytes are
/// cloned on the receive path.
pub struct ReceivedUdpDatagramView {
    frames: EthFrameStore,
    ip_fragments: Vec<IpFragmentInfo>,
    fragment_metadata: IpFragmentMetadata,
    udp_header: Option<UdpHeaderView>,
    payload_parts: Vec<PayloadPart>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
}

impl ReceivedUdpDatagramView {
    /// Constructs a new view. Used internally by the IPS receive path.
    pub(crate) fn new(
        eth_frames: Vec<Buf<Vec<u8>>>,
        ip_fragments: Vec<IpFragmentInfo>,
        fragment_metadata: IpFragmentMetadata,
        udp_header: Option<UdpHeaderView>,
        payload_parts: Vec<(usize, Range<usize>)>,
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) -> Self {
        Self {
            frames: EthFrameStore::from_frames(eth_frames),
            ip_fragments,
            fragment_metadata,
            udp_header,
            payload_parts: payload_parts
                .into_iter()
                .map(|(eth_frame_index, range)| PayloadPart { eth_frame_index, range })
                .collect(),
            src_ip,
            dst_ip,
        }
    }

    /// Source and destination IP addresses.
    pub fn addrs(&self) -> (IpAddr, IpAddr) {
        (self.src_ip, self.dst_ip)
    }

    /// Metadata describing IP fragment reception, including RFC 5722 events.
    pub fn ip_fragment_metadata(&self) -> &IpFragmentMetadata {
        &self.fragment_metadata
    }

    /// Parsed IP fragment information, one entry per received fragment.
    pub fn ip_fragments(&self) -> &[IpFragmentInfo] {
        &self.ip_fragments
    }

    /// Underlying Ethernet frame buffers.
    pub fn eth_frames(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.frames.eth_frames()
    }

    /// Parsed UDP header, if reassembly completed per RFC 5722.
    pub fn udp_header(&self) -> Option<&UdpHeaderView> {
        self.udp_header.as_ref()
    }

    /// UDP payload as an iovec-style slice list (zero-copy).
    ///
    /// Returns empty when reassembly was aborted (e.g. RFC 5722 overlap).
    pub fn payload_slices(&self) -> PayloadSliceView<'_> {
        PayloadSliceView { view: self }
    }

    /// UDP payload as a [`FragmentedByteSlice`] for checksum/filter-style APIs.
    ///
    /// `scratch` must hold at least as many entries as payload parts.
    pub fn payload<'a>(
        &'a self,
        scratch: &'a mut [&'a [u8]],
    ) -> FragmentedByteSlice<'a, &'a [u8]> {
        let parts = self.payload_parts.len();
        assert!(scratch.len() >= parts);
        for (i, part) in self.payload_parts.iter().enumerate() {
            scratch[i] = &self.frames.frames()[part.eth_frame_index].as_ref()[part.range.clone()];
        }
        FragmentedByteSlice::new(&mut scratch[..parts])
    }

}

/// Iovec-style read-only payload view.
pub struct PayloadSliceView<'a> {
    view: &'a ReceivedUdpDatagramView,
}

impl<'a> PayloadSliceView<'a> {
    /// Number of payload slices.
    pub fn len(&self) -> usize {
        self.view.payload_parts.len()
    }

    /// Returns true if there are no payload slices.
    pub fn is_empty(&self) -> bool {
        self.view.payload_parts.is_empty()
    }

    /// Iterates payload slices in reassembly order.
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.view.payload_parts.iter().map(|part| {
            &self.view.frames.frames()[part.eth_frame_index].as_ref()[part.range.clone()]
        })
    }
}

impl ReceivedUdpDatagramView {
    /// IPv4 source address convenience accessor.
    pub fn src_ipv4(&self) -> Option<Ipv4Addr> {
        match self.src_ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }
    }

    /// IPv6 source address convenience accessor.
    pub fn src_ipv6(&self) -> Option<Ipv6Addr> {
        match self.src_ip {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        }
    }

    /// Truncates a stored frame buffer to `new_len` bytes (no-op if already shorter).
    pub(crate) fn truncate_eth_frame(&mut self, index: usize, new_len: usize) -> bool {
        self.frames.truncate_eth_frame(index, new_len)
    }

    /// Drops Ethernet frame buffers after `keep_through_index` (inclusive).
    pub(crate) fn retain_eth_frames_through(&mut self, keep_through_index: usize) {
        self.frames.retain_eth_frames_through(keep_through_index);
    }

    /// Updates view metadata after shrinking to one unfragmented IPv4 frame in place.
    pub(crate) fn apply_single_frame_length_change(
        &mut self,
        frame_index: usize,
        ip_packet_range: Range<usize>,
        ip_body_range: Range<usize>,
        payload_range: Range<usize>,
        udp_length: u16,
    ) {
        let identification = self
            .ip_fragments
            .first()
            .map(|f| f.identification)
            .unwrap_or(0);
        let ip_fragment = IpFragmentInfo {
            eth_frame_index: frame_index,
            ip_packet_range,
            identification,
            fragment_offset: 0,
            more_fragments: false,
            ip_body_range,
        };
        self.ip_fragments = alloc::vec![ip_fragment.clone()];
        self.fragment_metadata.fragments = alloc::vec![ip_fragment];
        self.fragment_metadata.reassembly_outcome = ReassemblyOutcome::NotApplicable;
        self.fragment_metadata.events.clear();
        if let Some(hdr) = self.udp_header.as_mut() {
            hdr.length = udp_length;
            hdr.eth_frame_index = frame_index;
        }
        self.payload_parts = alloc::vec![PayloadPart {
            eth_frame_index: frame_index,
            range: payload_range,
        }];
    }

    pub(crate) fn write_payload_part(&mut self, part_index: usize, data: &[u8]) -> bool {
        let Some(part) = self.payload_parts.get(part_index) else {
            return false;
        };
        if part.range.len() != data.len() {
            return false;
        }
        let Some(frame) = self.frames.eth_frame_buf_mut(part.eth_frame_index) else {
            return false;
        };
        frame[part.range.clone()].copy_from_slice(data);
        true
    }

    pub(crate) fn update_udp_header_view(&mut self, length: u16) {
        if let Some(hdr) = self.udp_header.as_mut() {
            hdr.length = length;
        }
    }

    pub(crate) fn eth_frame_buf_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        self.frames.eth_frame_buf_mut(index)
    }

    pub(crate) fn eth_frame_buf(&self, index: usize) -> Option<&[u8]> {
        self.frames.eth_frame_buf(index)
    }

    pub(crate) fn ensure_eth_frame_len(&mut self, index: usize, min_len: usize) -> bool {
        self.frames.ensure_eth_frame_len(index, min_len)
    }
}

/// Parsed TCP header fields and their location within a stored frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeaderView {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub ack_flag: bool,
    pub syn_flag: bool,
    pub fin_flag: bool,
    pub rst_flag: bool,
    pub data_offset_bytes: u8,
    pub window: u16,
    pub eth_frame_index: usize,
    pub header_range: Range<usize>,
}

/// Zero-copy view of a received TCP segment for IPS analysis.
pub struct ReceivedTcpSegmentView {
    frames: EthFrameStore,
    ip_fragments: Vec<IpFragmentInfo>,
    fragment_metadata: IpFragmentMetadata,
    tcp_header: Option<TcpHeaderView>,
    payload_parts: Vec<PayloadPart>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
}

impl ReceivedTcpSegmentView {
    pub(crate) fn new(
        eth_frames: Vec<Buf<Vec<u8>>>,
        ip_fragments: Vec<IpFragmentInfo>,
        fragment_metadata: IpFragmentMetadata,
        tcp_header: Option<TcpHeaderView>,
        payload_parts: Vec<(usize, Range<usize>)>,
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) -> Self {
        Self {
            frames: EthFrameStore::from_frames(eth_frames),
            ip_fragments,
            fragment_metadata,
            tcp_header,
            payload_parts: payload_parts
                .into_iter()
                .map(|(eth_frame_index, range)| PayloadPart { eth_frame_index, range })
                .collect(),
            src_ip,
            dst_ip,
        }
    }

    pub fn addrs(&self) -> (IpAddr, IpAddr) {
        (self.src_ip, self.dst_ip)
    }

    pub fn ip_fragment_metadata(&self) -> &IpFragmentMetadata {
        &self.fragment_metadata
    }

    pub fn ip_fragments(&self) -> &[IpFragmentInfo] {
        &self.ip_fragments
    }

    pub fn eth_frames(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.frames.eth_frames()
    }

    pub fn tcp_header(&self) -> Option<&TcpHeaderView> {
        self.tcp_header.as_ref()
    }

    pub fn payload_slices(&self) -> TcpPayloadSliceView<'_> {
        TcpPayloadSliceView { view: self }
    }

    pub fn src_ipv4(&self) -> Option<Ipv4Addr> {
        match self.src_ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }
    }

    pub fn payload_len(&self) -> usize {
        self.payload_parts.iter().map(|p| p.range.len()).sum()
    }

    pub(crate) fn wire_payload_end(&self) -> Option<usize> {
        self.payload_parts.iter().map(|p| p.range.end).max()
    }

    pub(crate) fn truncate_eth_frame(&mut self, index: usize, new_len: usize) -> bool {
        self.frames.truncate_eth_frame(index, new_len)
    }

    pub(crate) fn retain_eth_frames_through(&mut self, keep_through_index: usize) {
        self.frames.retain_eth_frames_through(keep_through_index);
    }

    pub(crate) fn eth_frame_buf_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        self.frames.eth_frame_buf_mut(index)
    }

    pub(crate) fn eth_frame_buf(&self, index: usize) -> Option<&[u8]> {
        self.frames.eth_frame_buf(index)
    }

    pub(crate) fn ensure_eth_frame_len(&mut self, index: usize, min_len: usize) -> bool {
        self.frames.ensure_eth_frame_len(index, min_len)
    }

    pub(crate) fn apply_single_frame_length_change(
        &mut self,
        frame_index: usize,
        ip_packet_range: Range<usize>,
        ip_body_range: Range<usize>,
        payload_range: Range<usize>,
    ) {
        let identification = self.ip_fragments.first().map(|f| f.identification).unwrap_or(0);
        let ip_fragment = IpFragmentInfo {
            eth_frame_index: frame_index,
            ip_packet_range,
            identification,
            fragment_offset: 0,
            more_fragments: false,
            ip_body_range,
        };
        self.ip_fragments = alloc::vec![ip_fragment.clone()];
        self.fragment_metadata.fragments = alloc::vec![ip_fragment];
        self.fragment_metadata.reassembly_outcome = ReassemblyOutcome::NotApplicable;
        self.fragment_metadata.events.clear();
        if let Some(hdr) = self.tcp_header.as_mut() {
            hdr.eth_frame_index = frame_index;
        }
        self.payload_parts = alloc::vec![PayloadPart {
            eth_frame_index: frame_index,
            range: payload_range,
        }];
    }
}

pub struct TcpPayloadSliceView<'a> {
    view: &'a ReceivedTcpSegmentView,
}

impl<'a> TcpPayloadSliceView<'a> {
    pub fn len(&self) -> usize {
        self.view.payload_parts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.view.payload_parts.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.view.payload_parts.iter().map(|part| {
            &self.view.frames.frames()[part.eth_frame_index].as_ref()[part.range.clone()]
        })
    }
}

/// Parses a TCP header from frame bytes; returns None if too short.
pub(crate) fn parse_tcp_header(
    frame: &[u8],
    eth_frame_index: usize,
    tcp_start: usize,
) -> Option<TcpHeaderView> {
    if frame.len() < tcp_start + 20 {
        return None;
    }
    let data_offset = (frame[tcp_start + 12] >> 4) as usize * 4;
    if frame.len() < tcp_start + data_offset {
        return None;
    }
    let flags = frame[tcp_start + 13];
    Some(TcpHeaderView {
        src_port: u16::from_be_bytes([frame[tcp_start], frame[tcp_start + 1]]),
        dst_port: u16::from_be_bytes([frame[tcp_start + 2], frame[tcp_start + 3]]),
        seq_num: u32::from_be_bytes([
            frame[tcp_start + 4],
            frame[tcp_start + 5],
            frame[tcp_start + 6],
            frame[tcp_start + 7],
        ]),
        ack_num: u32::from_be_bytes([
            frame[tcp_start + 8],
            frame[tcp_start + 9],
            frame[tcp_start + 10],
            frame[tcp_start + 11],
        ]),
        ack_flag: flags & 0x10 != 0,
        syn_flag: flags & 0x02 != 0,
        fin_flag: flags & 0x01 != 0,
        rst_flag: flags & 0x04 != 0,
        data_offset_bytes: u8::try_from(data_offset).unwrap_or(255),
        window: u16::from_be_bytes([frame[tcp_start + 14], frame[tcp_start + 15]]),
        eth_frame_index,
        header_range: tcp_start..tcp_start + data_offset,
    })
}
