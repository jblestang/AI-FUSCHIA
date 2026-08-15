// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Per-segment TCP receive delivery with layered packet views for L7 inspection.
//!
//! # Processing delivered segments (L3 → L4 → L7)
//!
//! Bindings receive a [`TcpRecvSegment`] with a wire [`SharedPacketView`] plus
//! [`TcpSegmentReceiveMeta`]. Overlap/window trimming stays inside the TCP state
//! machine; metadata exposes sequence offsets so L7 can detect overlap.
//!
//! ```no_run
//! use net_types::ip::Ipv4;
//! use netstack3_tcp::{TcpRecvSegment, TcpSegmentReceiveMeta};
//!
//! fn process_delivered_tcp_segment(segment: &TcpRecvSegment<Ipv4>) -> Option<()> {
//!     // L3
//!     if segment.ip_meta.hop_limit == 0 {
//!         return None;
//!     }
//!
//!     // L4 + overlap hints (internal overlap trim is NOT re-run here)
//!     let TcpSegmentReceiveMeta { seq, seg_len, rcv_nxt, trim_prefix, .. } = segment.tcp;
//!     if segment.tcp.is_partial_overlap() {
//!         // e.g. retransmission overlapping RCV.NXT — inspect wire bytes in `view`
//!         let _ = (seq, seg_len, rcv_nxt, trim_prefix);
//!     }
//!
//!     // L7 only on bytes TCP accepted (sequence-space offset into payload)
//!     segment.with_accepted_payload(|payload| {
//!         for chunk in payload.iter_fragments() {
//!             handle_l7(chunk);
//!         }
//!     });
//!     Some(())
//! }
//!
//! fn handle_l7(_chunk: &[u8]) {}
//! ```

use alloc::sync::Arc;
use core::num::NonZeroU16;

use net_types::ip::{GenericOverIp, Ip};
use netstack3_base::{Payload, Segment, SeqNum, WindowSize};
use netstack3_ip::{IpReceiveMeta, SharedPacketView, transport_packet_view};
use packet::{FragmentedBytes, ParseMetadata};
use packet_formats::ip::DscpAndEcn;

/// TCP sequence metadata for a wire segment delivered to bindings.
///
/// Describes the segment as received on the wire. When [`Self::rcv_nxt`] is
/// present, overlap helpers compare against the connection's receive window at
/// delivery time — the same window math the state machine uses internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegmentReceiveMeta {
    /// Wire sequence number (SEG.SEQ).
    pub seq: SeqNum,
    /// Wire segment length in sequence-number space (SEG.LEN).
    pub seg_len: u32,
    /// RCV.NXT at delivery, if the connection had a receive window.
    pub rcv_nxt: Option<SeqNum>,
    /// Sequence-space bytes trimmed from the front by the internal window overlap step.
    pub trim_prefix: u32,
    /// Accepted length in sequence-number space after window trim.
    pub accepted_len: u32,
    /// Whether any part of the segment lies in the receive window.
    pub window_acceptable: bool,
}

impl TcpSegmentReceiveMeta {
    /// Builds metadata from a wire segment and the current receive window.
    pub fn from_segment_and_window<P: Payload>(
        segment: &Segment<P>,
        rcv_nxt: SeqNum,
        rwnd: WindowSize,
    ) -> Self {
        let seq = segment.header().seq;
        let seg_len = segment.len();
        let overlap = segment.receive_window_overlap(rcv_nxt, rwnd);
        Self {
            seq,
            seg_len,
            rcv_nxt: Some(rcv_nxt),
            trim_prefix: overlap.trim_prefix,
            accepted_len: overlap.accepted_len,
            window_acceptable: overlap.acceptable,
        }
    }

    /// Builds wire-only metadata when no receive window is available yet.
    pub fn from_segment_wire<P: Payload>(segment: &Segment<P>) -> Self {
        let seg_len = segment.len();
        Self {
            seq: segment.header().seq,
            seg_len,
            rcv_nxt: None,
            trim_prefix: 0,
            accepted_len: seg_len,
            window_acceptable: true,
        }
    }

    /// Sequence-space offset into the wire payload where accepted data begins.
    pub fn accepted_payload_offset(&self) -> u32 {
        self.trim_prefix
    }

    /// Accepted payload length in sequence-number space (may be zero).
    pub fn accepted_payload_len(&self) -> u32 {
        self.accepted_len.saturating_sub(self.control_len())
    }

    fn control_len(&self) -> u32 {
        // SYN/FIN occupy one sequence number each on the wire; overlap math in
        // `receive_window_overlap` already accounts for control bits.
        0
    }

    /// Segment starts before `RCV.NXT` (retransmission or overlap candidate).
    pub fn overlaps_rcv_nxt(&self) -> bool {
        let Some(rcv_nxt) = self.rcv_nxt else { return false };
        self.seq.before(rcv_nxt)
    }

    /// Segment spans `RCV.NXT` (classic overlap / retransmission pattern).
    pub fn is_partial_overlap(&self) -> bool {
        let Some(rcv_nxt) = self.rcv_nxt else { return false };
        self.seq.before(rcv_nxt) && (self.seq + self.seg_len).after(rcv_nxt)
    }

    /// Entire segment lies before `RCV.NXT` (fully duplicate).
    pub fn is_fully_duplicate(&self) -> bool {
        let Some(rcv_nxt) = self.rcv_nxt else { return false };
        !(self.seq + self.seg_len).after(rcv_nxt)
    }

    /// Internal window overlap would trim prefix and/or suffix.
    pub fn was_window_trimmed(&self) -> bool {
        self.trim_prefix > 0 || self.accepted_len < self.seg_len
    }
}

/// Layer-4 metadata for a received TCP segment.
#[derive(Debug, Clone, PartialEq, Eq, GenericOverIp)]
#[generic_over_ip(I, Ip)]
pub struct TcpPacketMeta<I: Ip> {
    /// Source IP address.
    pub src_ip: I::Addr,
    /// Source port.
    pub src_port: NonZeroU16,
    /// Destination IP address.
    pub dst_ip: I::Addr,
    /// Destination port.
    pub dst_port: NonZeroU16,
    /// DSCP and ECN from the IP header (also available in [`IpReceiveMeta`]).
    pub dscp_and_ecn: DscpAndEcn,
}

/// A received TCP segment delivered to bindings alongside stream reassembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRecvSegment<I: Ip> {
    /// Layer-4 metadata (addresses, ports).
    pub meta: TcpPacketMeta<I>,
    /// Layer-3 metadata from the IP header.
    pub ip_meta: IpReceiveMeta,
    /// TCP sequence / overlap metadata for the wire segment.
    pub tcp: TcpSegmentReceiveMeta,
    /// Full received frame with IP, transport, and payload layer ranges (wire bytes).
    pub view: SharedPacketView,
}

impl<I: Ip> TcpRecvSegment<I> {
    /// Attaches TCP sequence metadata computed at delivery time.
    pub fn with_tcp(mut self, tcp: TcpSegmentReceiveMeta) -> Self {
        self.tcp = tcp;
        self
    }

    /// Invokes `f` with the full TCP segment bytes (header + payload) as received on the wire.
    pub fn with_transport<R, F>(&self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, '_>) -> R,
    {
        self.view.with_transport(f)
    }

    /// Invokes `f` with the full wire payload (may extend beyond what TCP accepted).
    pub fn with_payload<R, F>(&self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, '_>) -> R,
    {
        self.view.with_payload(f)
    }

    /// Invokes `f` with payload bytes TCP accepted after window overlap (slice of wire payload).
    pub fn with_accepted_payload<R, F>(&self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, '_>) -> R,
    {
        let offset = usize::try_from(self.tcp.accepted_payload_offset()).unwrap_or(usize::MAX);
        let len = usize::try_from(self.tcp.accepted_payload_len()).unwrap_or(0);
        self.view.with_payload(|payload| {
            let mut slices: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::new();
            let mut skip = offset;
            let mut remain = len;
            for chunk in payload.iter_fragments() {
                if remain == 0 {
                    break;
                }
                if skip >= chunk.len() {
                    skip -= chunk.len();
                    continue;
                }
                let start = skip;
                skip = 0;
                let take = core::cmp::min(remain, chunk.len() - start);
                slices.push(&chunk[start..start + take]);
                remain -= take;
            }
            f(FragmentedBytes::new(&mut slices))
        })
    }

    /// Invokes `f` with the full IP datagram bytes.
    pub fn with_ip_datagram<R, F>(&self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, '_>) -> R,
    {
        self.view.with_ip_datagram(f)
    }
}

/// Builds a [`TcpRecvSegment`] from pinned RX storage and parsed header info.
pub fn build_tcp_recv_segment<I: Ip, H: netstack3_ip::IpHeaderInfo<I>>(
    meta: TcpPacketMeta<I>,
    header_info: &H,
    frame_storage: &Option<Arc<[u8]>>,
    transport_slice: &[u8],
    parse_meta: ParseMetadata,
    tcp: TcpSegmentReceiveMeta,
) -> TcpRecvSegment<I> {
    TcpRecvSegment {
        meta,
        ip_meta: IpReceiveMeta::from_header(header_info),
        tcp,
        view: transport_packet_view(frame_storage, transport_slice, parse_meta),
    }
}

/// Wire-only segment builder used at IP ingress before RCV.NXT is known.
pub fn build_wire_tcp_recv_segment<I: Ip, H: netstack3_ip::IpHeaderInfo<I>>(
    meta: TcpPacketMeta<I>,
    header_info: &H,
    frame_storage: &Option<Arc<[u8]>>,
    transport_slice: &[u8],
    parse_meta: ParseMetadata,
    segment: &Segment<impl Payload>,
) -> TcpRecvSegment<I> {
    build_tcp_recv_segment(
        meta,
        header_info,
        frame_storage,
        transport_slice,
        parse_meta,
        TcpSegmentReceiveMeta::from_segment_wire(segment),
    )
}

/// Returns the TCP segment bytes (header + payload) within a parsed segment buffer.
pub(crate) fn tcp_transport_slice<'a>(
    segment: &'a packet_formats::tcp::TcpSegment<&[u8]>,
    parse_meta: ParseMetadata,
) -> &'a [u8] {
    let header_len = parse_meta.header_len();
    let total_len = header_len + parse_meta.body_len();
    let body = segment.body();
    // SAFETY: TCP header and body are contiguous in the original RX buffer.
    unsafe { core::slice::from_raw_parts(body.as_ptr().sub(header_len), total_len) }
}

#[cfg(test)]
mod process_example {
    use core::num::NonZeroU16;

    use net_types::ip::{Ipv4, Ipv4Addr};
    use netstack3_base::{Segment, SeqNum, VerifiedTcpSegment, WindowSize};
    use netstack3_base::NetworkSerializationContext;
    use netstack3_ip::testutil::FakeIpHeaderInfo;
    use packet::{Buf, NestablePacketBuilder as _, ParsablePacket, ParseBuffer};
    use packet_formats::tcp::{TcpParseArgs, TcpSegment, TcpSegmentBuilder};

    use super::*;

    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
    const REMOTE_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);
    const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(80).unwrap();
    const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(443).unwrap();

    fn build_test_segment(payload: &[u8], seq: u32) -> TcpRecvSegment<Ipv4> {
        let mut builder =
            TcpSegmentBuilder::new(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, seq, None, u16::MAX);
        builder.ack(true);
        let transport = builder
            .wrap_body(Buf::new(payload, ..))
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        let frame: Arc<[u8]> = Arc::from(transport);
        let transport_slice = frame.as_ref();
        let mut parse_buf = transport_slice;
        let packet = parse_buf
            .parse_with::<_, TcpSegment<_>>(TcpParseArgs::new(REMOTE_IP, LOCAL_IP))
            .unwrap();
        let parse_meta = ParsablePacket::parse_metadata(&packet);
        let header_info = FakeIpHeaderInfo { hop_limit: 64, ..Default::default() };
        let incoming: Segment<&[u8]> = (&packet).into();
        build_wire_tcp_recv_segment(
            TcpPacketMeta {
                src_ip: REMOTE_IP,
                src_port: REMOTE_PORT,
                dst_ip: LOCAL_IP,
                dst_port: LOCAL_PORT,
                dscp_and_ecn: header_info.dscp_and_ecn(),
            },
            &header_info,
            &Some(frame),
            transport_slice,
            parse_meta,
            &incoming,
        )
    }

    fn process_delivered_tcp_segment(segment: &TcpRecvSegment<Ipv4>) -> Option<usize> {
        if segment.ip_meta.hop_limit == 0 {
            return None;
        }

        if segment.tcp.is_partial_overlap() {
            // Wire view still holds full bytes; accepted slice is what TCP ingests.
            let _wire_len = segment.with_payload(|p| p.len());
            let _accepted_len = segment.with_accepted_payload(|p| p.len());
        }

        Some(segment.with_accepted_payload(|payload| {
            payload.iter_fragments().map(|c| c.len()).sum()
        }))
    }

    #[test]
    fn process_delivered_tcp_segment_example() {
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let segment = build_test_segment(payload, 1000);
        let len = process_delivered_tcp_segment(&segment).expect("segment should pass");
        assert_eq!(len, payload.len());
    }

    #[test]
    fn overlap_metadata_detects_partial_retransmission() {
        let payload = b"hello";
        let mut builder = TcpSegmentBuilder::new(
            REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1000, None, u16::MAX,
        );
        let transport = builder
            .wrap_body(Buf::new(payload, ..))
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        let mut parse_buf = transport.as_slice();
        let packet = parse_buf
            .parse_with::<_, TcpSegment<_>>(TcpParseArgs::new(REMOTE_IP, LOCAL_IP))
            .unwrap();
        let verified = VerifiedTcpSegment::try_from(packet).unwrap();
        let incoming: Segment<&[u8]> = (&verified).into();
        let meta = TcpSegmentReceiveMeta::from_segment_and_window(
            &incoming,
            SeqNum::new(1003),
            WindowSize::MAX,
        );
        assert!(meta.is_partial_overlap());
        assert_eq!(meta.trim_prefix, 3);
        assert_eq!(meta.accepted_payload_len(), 2);
    }
}
