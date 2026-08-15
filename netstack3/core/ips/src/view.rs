// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Multi-layer zero-copy views delivered to Layer 7 IPS analysis.

use alloc::vec::Vec;
use core::ops::Range;

use net_types::ip::{IpAddr, Ipv4Addr, Ipv6Addr};
use packet::{Buf, BufferMut, FragmentedByteSlice};

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
    /// Owned Ethernet frame buffers (driver RX memory).
    eth_frames: Vec<Buf<Vec<u8>>>,
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
            eth_frames,
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
        self.eth_frames.iter().map(|f| f.as_ref())
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
            scratch[i] = &self.eth_frames[part.eth_frame_index].as_ref()[part.range.clone()];
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
            &self.view.eth_frames[part.eth_frame_index].as_ref()[part.range.clone()]
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

    /// Applies metadata after consolidating to a single unfragmented IPv4 frame.
    pub(crate) fn apply_unfragmented_overwrite(
        &mut self,
        eth_frames: Vec<Buf<Vec<u8>>>,
        ip_fragment: IpFragmentInfo,
        udp_header: UdpHeaderView,
        payload_range: Range<usize>,
    ) {
        self.eth_frames = eth_frames;
        self.ip_fragments = alloc::vec![ip_fragment.clone()];
        self.fragment_metadata.fragments = alloc::vec![ip_fragment];
        self.fragment_metadata.reassembly_outcome = ReassemblyOutcome::NotApplicable;
        self.fragment_metadata.events.clear();
        self.udp_header = Some(udp_header);
        self.payload_parts = alloc::vec![PayloadPart {
            eth_frame_index: 0,
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
        let frame = &mut self.eth_frames[part.eth_frame_index];
        frame.as_mut()[part.range.clone()].copy_from_slice(data);
        true
    }

    pub(crate) fn update_udp_header_view(&mut self, length: u16) {
        if let Some(hdr) = self.udp_header.as_mut() {
            hdr.length = length;
        }
    }

    pub(crate) fn eth_frame_buf_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        Some(self.eth_frames.get_mut(index)?.as_mut())
    }

    pub(crate) fn eth_frame_buf(&self, index: usize) -> Option<&[u8]> {
        Some(self.eth_frames.get(index)?.as_ref())
    }

    pub(crate) fn ensure_eth_frame_len(&mut self, index: usize, min_len: usize) -> bool {
        let Some(frame) = self.eth_frames.get(index) else {
            return false;
        };
        if frame.as_ref().len() >= min_len {
            return true;
        }
        let mut bytes = frame.as_ref().to_vec();
        bytes.resize(min_len, 0);
        self.eth_frames[index] = Buf::new(bytes, ..);
        true
    }
}
