// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Multi-layer zero-copy views delivered to Layer 7 IPS analysis.

use alloc::vec::Vec;
use core::ops::Range;

use net_types::ethernet::Mac;
use net_types::ip::{IpAddr, IpVersionMarker, Ipv4, Ipv4Addr, Ipv6Addr};
use packet::{Buf, FragmentedByteSlice, ParseBuffer, ParsablePacket};
use packet_formats::ethernet::{
    EtherType, EthernetFrame, EthernetFrameLengthCheck, ETHERNET_HDR_LEN_NO_TAG,
};
use packet_formats::tcp::{TcpParseArgs, TcpSegment};
use packet_formats::testutil::ForceSkipChecksumValidation;
use packet_formats::udp::{UdpPacketRaw, HEADER_BYTES as UDP_HEADER_BYTES};

use crate::frame_store::EthFrameStore;
use crate::wire::{self, UDP_LENGTH_OFFSET};

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

/// Parsed Ethernet header fields and their location within a stored frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetHeaderView {
    /// Source MAC address from the Ethernet header.
    pub src_mac: Mac,
    /// Destination MAC address from the Ethernet header.
    pub dst_mac: Mac,
    /// EtherType when the header field encodes a type (not an IEEE 802.3 length).
    pub ethertype: Option<EtherType>,
    /// Index into [`ReceivedUdpDatagramView::eth_frames`].
    pub eth_frame_index: usize,
    /// Byte range of the Ethernet header within the frame buffer.
    pub header_range: Range<usize>,
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
    ethernet_header: Option<EthernetHeaderView>,
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
        let ethernet_header = ethernet_header_for_frames(&eth_frames, &ip_fragments);
        Self {
            frames: EthFrameStore::from_frames(eth_frames),
            ip_fragments,
            fragment_metadata,
            ethernet_header,
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

    /// Parsed Ethernet header from the first IP fragment's backing frame.
    pub fn ethernet_header(&self) -> Option<&EthernetHeaderView> {
        self.ethernet_header.as_ref()
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
        if let Some(hdr) = self.ethernet_header.as_mut() {
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
    ethernet_header: Option<EthernetHeaderView>,
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
        let ethernet_header = ethernet_header_for_frames(&eth_frames, &ip_fragments);
        Self {
            frames: EthFrameStore::from_frames(eth_frames),
            ip_fragments,
            fragment_metadata,
            ethernet_header,
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

    /// Parsed Ethernet header from the first IP fragment's backing frame.
    pub fn ethernet_header(&self) -> Option<&EthernetHeaderView> {
        self.ethernet_header.as_ref()
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
        if let Some(hdr) = self.ethernet_header.as_mut() {
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

/// Minimum ICMP/ICMPv6 header length (type, code, checksum) per RFC 792 / RFC 4443.
pub const ICMP_HEADER_PREFIX_LEN: usize = 4;

/// Parsed ICMP header fields and their location within a stored frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpHeaderView {
    /// ICMP message type.
    pub msg_type: u8,
    /// ICMP message code.
    pub code: u8,
    /// Index into [`ReceivedIcmpMessageView::eth_frames`].
    pub eth_frame_index: usize,
    /// Byte range of the 4-byte ICMP header prefix within the frame buffer.
    pub header_range: Range<usize>,
}

/// Zero-copy view of a received ICMP message for IPS analysis.
pub struct ReceivedIcmpMessageView {
    frames: EthFrameStore,
    ip_fragments: Vec<IpFragmentInfo>,
    fragment_metadata: IpFragmentMetadata,
    ethernet_header: Option<EthernetHeaderView>,
    icmp_header: Option<IcmpHeaderView>,
    payload_parts: Vec<PayloadPart>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
}

impl ReceivedIcmpMessageView {
    pub(crate) fn new(
        eth_frames: Vec<Buf<Vec<u8>>>,
        ip_fragments: Vec<IpFragmentInfo>,
        fragment_metadata: IpFragmentMetadata,
        icmp_header: Option<IcmpHeaderView>,
        payload_parts: Vec<(usize, Range<usize>)>,
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) -> Self {
        let ethernet_header = ethernet_header_for_frames(&eth_frames, &ip_fragments);
        Self {
            frames: EthFrameStore::from_frames(eth_frames),
            ip_fragments,
            fragment_metadata,
            ethernet_header,
            icmp_header,
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

    /// Parsed Ethernet header from the first IP fragment's backing frame.
    pub fn ethernet_header(&self) -> Option<&EthernetHeaderView> {
        self.ethernet_header.as_ref()
    }

    /// Parsed ICMP header prefix (type, code, checksum).
    pub fn icmp_header(&self) -> Option<&IcmpHeaderView> {
        self.icmp_header.as_ref()
    }

    /// ICMP message body after the 4-byte header prefix (zero-copy).
    pub fn payload_slices(&self) -> IcmpPayloadSliceView<'_> {
        IcmpPayloadSliceView { view: self }
    }

    pub fn src_ipv4(&self) -> Option<Ipv4Addr> {
        match self.src_ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }
    }

    pub fn src_ipv6(&self) -> Option<Ipv6Addr> {
        match self.src_ip {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        }
    }
}

/// Iovec-style read-only ICMP body view (bytes after the 4-octet header prefix).
pub struct IcmpPayloadSliceView<'a> {
    view: &'a ReceivedIcmpMessageView,
}

impl<'a> IcmpPayloadSliceView<'a> {
    /// Number of payload slices.
    pub fn len(&self) -> usize {
        self.view.payload_parts.len()
    }

    /// Returns true if there are no payload slices.
    pub fn is_empty(&self) -> bool {
        self.view.payload_parts.is_empty()
    }

    /// Iterates payload slices in order.
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.view.payload_parts.iter().map(|part| {
            &self.view.frames.frames()[part.eth_frame_index].as_ref()[part.range.clone()]
        })
    }
}

/// Minimum IGMP header prefix length (type, max resp code, checksum) per RFC 3376.
pub const IGMP_HEADER_PREFIX_LEN: usize = 4;

/// Parsed IGMP header fields and their location within a stored frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpHeaderView {
    /// IGMP message type (e.g. 0x22 = IGMPv3 Membership Report).
    pub msg_type: u8,
    /// Max Response Code field (meaningful for queries; zero in reports).
    pub max_resp_code: u8,
    /// Index into [`ReceivedIgmpMessageView::eth_frames`].
    pub eth_frame_index: usize,
    /// Byte range of the 4-byte IGMP header prefix within the frame buffer.
    pub header_range: Range<usize>,
}

/// Zero-copy view of a received IGMP message for IPS analysis.
pub struct ReceivedIgmpMessageView {
    frames: EthFrameStore,
    ip_fragments: Vec<IpFragmentInfo>,
    fragment_metadata: IpFragmentMetadata,
    ethernet_header: Option<EthernetHeaderView>,
    igmp_header: Option<IgmpHeaderView>,
    payload_parts: Vec<PayloadPart>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
}

impl ReceivedIgmpMessageView {
    pub(crate) fn new(
        eth_frames: Vec<Buf<Vec<u8>>>,
        ip_fragments: Vec<IpFragmentInfo>,
        fragment_metadata: IpFragmentMetadata,
        igmp_header: Option<IgmpHeaderView>,
        payload_parts: Vec<(usize, Range<usize>)>,
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) -> Self {
        let ethernet_header = ethernet_header_for_frames(&eth_frames, &ip_fragments);
        Self {
            frames: EthFrameStore::from_frames(eth_frames),
            ip_fragments,
            fragment_metadata,
            ethernet_header,
            igmp_header,
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

    pub fn ip_fragment_metadata(&self) -> &IpFragmentMetadata {
        &self.fragment_metadata
    }

    pub fn ip_fragments(&self) -> &[IpFragmentInfo] {
        &self.ip_fragments
    }

    pub fn eth_frames(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.frames.eth_frames()
    }

    pub fn ethernet_header(&self) -> Option<&EthernetHeaderView> {
        self.ethernet_header.as_ref()
    }

    /// Parsed IGMP header prefix (type, max resp code, checksum).
    pub fn igmp_header(&self) -> Option<&IgmpHeaderView> {
        self.igmp_header.as_ref()
    }

    /// IGMP message body after the 4-byte header prefix (zero-copy).
    pub fn payload_slices(&self) -> IgmpPayloadSliceView<'_> {
        IgmpPayloadSliceView { view: self }
    }

    pub fn src_ipv4(&self) -> Option<Ipv4Addr> {
        match self.src_ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }
    }
}

/// Iovec-style read-only IGMP body view (bytes after the 4-octet header prefix).
pub struct IgmpPayloadSliceView<'a> {
    view: &'a ReceivedIgmpMessageView,
}

impl<'a> IgmpPayloadSliceView<'a> {
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

/// Parses an untagged Ethernet header from frame bytes; returns None if too short.
pub(crate) fn parse_ethernet_header(
    frame: &[u8],
    eth_frame_index: usize,
) -> Option<EthernetHeaderView> {
    let mut bytes = frame;
    let eth = bytes
        .parse_with::<_, EthernetFrame<_>>(EthernetFrameLengthCheck::NoCheck)
        .ok()?;
    Some(EthernetHeaderView {
        src_mac: eth.src_mac(),
        dst_mac: eth.dst_mac(),
        ethertype: eth.ethertype(),
        eth_frame_index,
        header_range: 0..ETHERNET_HDR_LEN_NO_TAG,
    })
}

fn ethernet_header_for_frames(
    eth_frames: &[Buf<Vec<u8>>],
    ip_fragments: &[IpFragmentInfo],
) -> Option<EthernetHeaderView> {
    let frame_index = ip_fragments
        .iter()
        .find(|f| f.fragment_offset == 0)
        .map(|f| f.eth_frame_index)
        .unwrap_or(0);
    let frame = eth_frames.get(frame_index)?;
    parse_ethernet_header(frame.as_ref(), frame_index)
}

/// Parses a UDP header from frame bytes; returns None if too short.
pub(crate) fn parse_udp_header(
    frame: &[u8],
    eth_frame_index: usize,
    udp_start: usize,
) -> Option<UdpHeaderView> {
    let header_range = udp_start..udp_start + UDP_HEADER_BYTES;
    if frame.len() < header_range.end {
        return None;
    }
    let mut bytes = &frame[header_range.clone()];
    let raw = UdpPacketRaw::parse(&mut bytes, IpVersionMarker::<Ipv4>::default()).ok()?;
    if frame.len() < header_range.end {
        return None;
    }
    let hdr_bytes = &frame[header_range.clone()];
    let length = u16::from_be_bytes([
        hdr_bytes[UDP_LENGTH_OFFSET],
        hdr_bytes[UDP_LENGTH_OFFSET + 1],
    ]);
    Some(UdpHeaderView {
        src_port: raw.src_port().map(|p| p.get()).unwrap_or(0),
        dst_port: raw.dst_port()?.get(),
        length,
        eth_frame_index,
        header_range,
    })
}

/// Parses a TCP header from frame bytes; returns None if too short.
pub(crate) fn parse_tcp_header(
    frame: &[u8],
    eth_frame_index: usize,
    tcp_start: usize,
) -> Option<TcpHeaderView> {
    if frame.len() < tcp_start + wire::TCP_HDR_PREFIX_LEN {
        return None;
    }
    let mut bytes = &frame[tcp_start..];
    let args = TcpParseArgs::with_context(
        Ipv4Addr::new([0, 0, 0, 0]),
        Ipv4Addr::new([0, 0, 0, 0]),
        ForceSkipChecksumValidation(true),
    );
    let segment = TcpSegment::parse(&mut bytes, args).ok()?;
    let header_len = segment.header_len();
    if frame.len() < tcp_start + header_len {
        return None;
    }
    Some(TcpHeaderView {
        src_port: segment.src_port().get(),
        dst_port: segment.dst_port().get(),
        seq_num: segment.seq_num(),
        ack_num: segment.ack_num().unwrap_or(0),
        ack_flag: segment.ack_num().is_some(),
        syn_flag: segment.syn(),
        fin_flag: segment.fin(),
        rst_flag: segment.rst(),
        data_offset_bytes: u8::try_from(header_len).unwrap_or(u8::MAX),
        window: segment.window_size(),
        eth_frame_index,
        header_range: tcp_start..tcp_start + header_len,
    })
}

/// Parses an ICMP header prefix from frame bytes; returns None if too short.
pub(crate) fn parse_icmp_header(
    frame: &[u8],
    eth_frame_index: usize,
    icmp_start: usize,
) -> Option<IcmpHeaderView> {
    let header_range = icmp_start..icmp_start + ICMP_HEADER_PREFIX_LEN;
    if frame.len() < header_range.end {
        return None;
    }
    Some(IcmpHeaderView {
        msg_type: frame[icmp_start],
        code: frame[icmp_start + 1],
        eth_frame_index,
        header_range,
    })
}

/// Parses an IGMP header prefix from frame bytes; returns None if too short.
pub(crate) fn parse_igmp_header(
    frame: &[u8],
    eth_frame_index: usize,
    igmp_start: usize,
) -> Option<IgmpHeaderView> {
    let header_range = igmp_start..igmp_start + IGMP_HEADER_PREFIX_LEN;
    if frame.len() < header_range.end {
        return None;
    }
    Some(IgmpHeaderView {
        msg_type: frame[igmp_start],
        max_resp_code: frame[igmp_start + 1],
        eth_frame_index,
        header_range,
    })
}

#[cfg(test)]
mod tests {
    use net_types::ethernet::Mac;
    use netstack3_base::NetworkSerializationContext;
    use packet::{Buf, NestableSerializer as _, Serializer};
    use packet_formats::ethernet::{EtherType, EthernetFrameBuilder};

    use super::*;

    fn serialize_ethernet_frame(src: Mac, dst: Mac, ethertype: EtherType) -> Vec<u8> {
        let eth = EthernetFrameBuilder::new(src, dst, ethertype, 0);
        Buf::new(alloc::vec![], ..)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner()
    }

    #[test]
    fn parse_ethernet_header_reads_mac_and_ethertype() {
        const SRC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
        const DST: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
        let frame = serialize_ethernet_frame(SRC, DST, EtherType::Ipv4);

        let hdr = parse_ethernet_header(&frame, 0).expect("ethernet header");
        assert_eq!(hdr.dst_mac, DST);
        assert_eq!(hdr.src_mac, SRC);
        assert_eq!(hdr.ethertype, Some(EtherType::Ipv4));
        assert_eq!(hdr.header_range, 0..ETHERNET_HDR_LEN_NO_TAG);
    }

    #[test]
    fn received_view_populates_ethernet_header_from_first_fragment() {
        const SRC: Mac = Mac::new([0xBB; Mac::BYTES]);
        const DST: Mac = Mac::new([0xAA; Mac::BYTES]);
        let frame = serialize_ethernet_frame(SRC, DST, EtherType::Ipv6);

        let view = ReceivedUdpDatagramView::new(
            alloc::vec![Buf::new(frame, ..)],
            alloc::vec![IpFragmentInfo {
                eth_frame_index: 0,
                ip_packet_range: ETHERNET_HDR_LEN_NO_TAG..ETHERNET_HDR_LEN_NO_TAG,
                identification: 1,
                fragment_offset: 0,
                more_fragments: false,
                ip_body_range: ETHERNET_HDR_LEN_NO_TAG..ETHERNET_HDR_LEN_NO_TAG,
            }],
            IpFragmentMetadata::default(),
            None,
            alloc::vec![],
            IpAddr::V4(Ipv4Addr::new([192, 0, 2, 1])),
            IpAddr::V4(Ipv4Addr::new([192, 0, 2, 2])),
        );

        let eth = view.ethernet_header().expect("ethernet view");
        assert_eq!(eth.src_mac, SRC);
        assert_eq!(eth.dst_mac, DST);
        assert_eq!(eth.ethertype, Some(EtherType::Ipv6));
    }
}
