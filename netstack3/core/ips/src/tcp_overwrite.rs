// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! In-place TCP prefix-keep edits with sequence/ACK mangling.
//!
//! v1 scope: **established-flow data only** — [`TcpOverwriter::apply_edit`] rejects
//! SYN/FIN/RST. SACK block edges are rewritten using reverse-direction stream state;
//! URG is cleared when the urgent pointer falls outside the kept payload prefix.

use internet_checksum::Checksum;
use net_types::ip::{IpAddr, Ipv4Addr};
use packet_formats::ip::IpProto;
use packet_formats::ipv4::HDR_PREFIX_LEN;

use crate::tcp_flow::{InboundSegmentClass, TcpFlowDirection, TcpFlowState};
use crate::view::{ReceivedTcpSegmentView, ReassemblyOutcome};

const IPV4_TOTAL_LEN_OFFSET: usize = 2;
const IPV4_FLAGS_FRAG_OFFSET: usize = 6;
const IPV4_HDR_CHECKSUM_OFFSET: usize = 10;
const TCP_SEQ_OFFSET: usize = 4;
const TCP_ACK_OFFSET: usize = 8;
const TCP_FLAGS_OFFSET: usize = 13;
const TCP_URG_OFFSET: usize = 18;
const TCP_CHECKSUM_OFFSET: usize = 16;
const TCP_FLAG_URG: u8 = 0x20;
const TCP_OPTION_KIND_NOP: u8 = 1;
const TCP_OPTION_KIND_SACK_PERMITTED: u8 = 4;
const TCP_OPTION_KIND_SACK: u8 = 5;

/// How [`TcpOverwriter`] updates checksum fields after a rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpOverwriteChecksum {
    #[default]
    NicOffload,
    ComputeInSoftware,
}

/// Prefix-keep edit: retain first `keep_len` payload bytes, drop the tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpPayloadEdit {
    pub keep_len: usize,
}

/// Result of inbound classification + header preparation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpForwardAction {
    /// Segment should not be forwarded (dropped retransmit).
    Suppressed,
    /// Headers patched; segment ready for egress.
    Forward,
}

/// Errors from [`TcpOverwriter`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOverwriteError {
    ReassemblyAborted,
    ReassemblyIncomplete,
    MissingTcpHeader,
    UnsupportedIpVersion,
    KeepLenExceedsPayload { keep_len: usize, payload_len: usize },
    /// Segment carries SYN, FIN, or RST; v1 edits apply to established data only.
    ControlSegmentNotEditable,
    UnknownFlow,
}

pub struct TcpOverwriter<'a> {
    view: &'a mut ReceivedTcpSegmentView,
    flow: &'a mut TcpFlowState,
    direction: TcpFlowDirection,
    checksum: TcpOverwriteChecksum,
}

impl<'a> TcpOverwriter<'a> {
    pub fn new(
        view: &'a mut ReceivedTcpSegmentView,
        flow: &'a mut TcpFlowState,
        direction: TcpFlowDirection,
    ) -> Self {
        Self { view, flow, direction, checksum: TcpOverwriteChecksum::default() }
    }

    pub fn with_checksum(
        view: &'a mut ReceivedTcpSegmentView,
        flow: &'a mut TcpFlowState,
        direction: TcpFlowDirection,
        checksum: TcpOverwriteChecksum,
    ) -> Self {
        Self { view, flow, direction, checksum }
    }

    /// Classifies an inbound segment and patches seq/ack without payload edit.
    pub fn prepare_inbound(&mut self) -> Result<TcpForwardAction, TcpOverwriteError> {
        self.validate_writable()?;
        if let Some(hdr) = self.view.tcp_header() {
            self.flow.note_control_flags(self.direction, hdr.fin_flag, hdr.rst_flag);
        }
        let (raw_seq, payload_len, ack_flag, raw_ack) = self.header_fields()?;
        let payload_len_u32 = payload_len as u32;
        let class = self.flow.classify_inbound(self.direction, raw_seq, payload_len_u32);
        match class {
            InboundSegmentClass::RetransmitDropped => Ok(TcpForwardAction::Suppressed),
            InboundSegmentClass::RetransmitKeptPrefix => {
                let keep = self.flow.retrim_keep_len(self.direction, raw_seq, payload_len as u32);
                let removed = payload_len_u32.saturating_sub(keep);
                self.truncate_payload(keep as usize)?;
                self.patch_headers_only(raw_seq, ack_flag, Some(raw_ack), removed)?;
                Ok(TcpForwardAction::Forward)
            }
            InboundSegmentClass::OutOfOrderHold => Ok(TcpForwardAction::Suppressed),
            InboundSegmentClass::NewData => {
                self.patch_headers_only(
                    raw_seq,
                    ack_flag,
                    if ack_flag { Some(raw_ack) } else { None },
                    0,
                )?;
                Ok(TcpForwardAction::Forward)
            }
        }
    }

    /// L7 validated prefix; drop incomplete tail and update flow state.
    pub fn apply_edit(&mut self, edit: TcpPayloadEdit) -> Result<(), TcpOverwriteError> {
        self.validate_writable()?;
        self.validate_established_data_segment()?;
        let (raw_seq, payload_len, ack_flag, raw_ack) = self.header_fields()?;
        let payload_len_u32 = payload_len as u32;
        if edit.keep_len > payload_len {
            return Err(TcpOverwriteError::KeepLenExceedsPayload {
                keep_len: edit.keep_len,
                payload_len,
            });
        }
        self.truncate_payload(edit.keep_len)?;
        let removed = (payload_len_u32).saturating_sub(edit.keep_len as u32);
        self.patch_headers_only(raw_seq, ack_flag, Some(raw_ack), removed)?;
        self.flow
            .apply_keep_edit(self.direction, raw_seq, payload_len_u32, edit.keep_len as u32);
        Ok(())
    }

    fn truncate_payload(&mut self, keep_len: usize) -> Result<(), TcpOverwriteError> {
        if self.is_single_part_unfragmented() {
            self.truncate_single_frame(keep_len)?;
        } else if keep_len <= self.view.payload_len() {
            self.shrink_to_single_frame(keep_len)?;
        } else {
            return Err(TcpOverwriteError::KeepLenExceedsPayload {
                keep_len,
                payload_len: self.view.payload_len(),
            });
        }
        Ok(())
    }

    /// Bytes removed from this segment in the current operation; excluded from
    /// seq mangling so the edited segment keeps its original start seq.
    fn patch_headers_only(
        &mut self,
        raw_seq: u32,
        ack_flag: bool,
        raw_ack: Option<u32>,
        removing_from_this_segment: u32,
    ) -> Result<(), TcpOverwriteError> {
        let tcp_hdr = self.view.tcp_header().expect("validated").clone();
        let delta = self.flow.direction_delta(self.direction);
        let seq = raw_seq.wrapping_sub(delta.saturating_sub(removing_from_this_segment));
        let (_, ack) =
            self.flow.translate_outbound(self.direction, raw_seq, raw_ack, ack_flag);
        let frame_index = tcp_hdr.eth_frame_index;
        let wire_payload_len = self.view.payload_len();
        let buf = self
            .view
            .eth_frame_buf_mut(frame_index)
            .ok_or(TcpOverwriteError::MissingTcpHeader)?;
        let tcp_start = tcp_hdr.header_range.start;
        buf[tcp_start + TCP_SEQ_OFFSET..tcp_start + TCP_SEQ_OFFSET + 4]
            .copy_from_slice(&seq.to_be_bytes());
        if ack_flag {
            if let Some(a) = ack {
                buf[tcp_start + TCP_ACK_OFFSET..tcp_start + TCP_ACK_OFFSET + 4]
                    .copy_from_slice(&a.to_be_bytes());
            }
        }
        adjust_urg_pointer(buf, tcp_start, wire_payload_len);
        if self.flow.has_mangling() || removing_from_this_segment > 0 {
            rewrite_sack_options(
                buf,
                tcp_start,
                tcp_hdr.data_offset_bytes as usize,
                self.flow,
                self.direction,
            );
        }
        self.refresh_lengths_and_checksums(frame_index, tcp_start)?;
        Ok(())
    }

    fn truncate_single_frame(&mut self, keep_len: usize) -> Result<(), TcpOverwriteError> {
        let tcp_hdr = self.view.tcp_header().expect("validated").clone();
        let frag = self.view.ip_fragments().first().expect("fragment").clone();
        let payload_start = tcp_hdr.header_range.end;
        let payload_end = payload_start + keep_len;
        let frame_index = frag.eth_frame_index;
        self.view.truncate_eth_frame(frame_index, payload_end);
        let ip_offset = frag.ip_packet_range.start;
        self.view.apply_single_frame_length_change(
            frame_index,
            ip_offset..payload_end,
            tcp_hdr.header_range.start..payload_end,
            payload_start..payload_end,
        );
        Ok(())
    }

    fn shrink_to_single_frame(&mut self, keep_len: usize) -> Result<(), TcpOverwriteError> {
        let first_frag = self.view.ip_fragments().first().expect("fragment").clone();
        let tcp_hdr = self.view.tcp_header().expect("validated").clone();
        let ip_offset = first_frag.ip_packet_range.start;
        let payload_start = tcp_hdr.header_range.end;
        let payload_end = payload_start + keep_len;
        let frame_index = first_frag.eth_frame_index;
        self.view.truncate_eth_frame(frame_index, payload_end);
        self.view.retain_eth_frames_through(frame_index);
        self.view.apply_single_frame_length_change(
            frame_index,
            ip_offset..payload_end,
            tcp_hdr.header_range.start..payload_end,
            payload_start..payload_end,
        );
        Ok(())
    }

    fn refresh_lengths_and_checksums(
        &mut self,
        frame_index: usize,
        tcp_start: usize,
    ) -> Result<(), TcpOverwriteError> {
        let tcp_hdr = self.view.tcp_header().expect("validated").clone();
        let frag = self
            .view
            .ip_fragments()
            .iter()
            .find(|f| f.eth_frame_index == frame_index)
            .expect("fragment");
        let ip_offset = frag.ip_packet_range.start;
        let payload_end = self.view.wire_payload_end().unwrap_or(tcp_hdr.header_range.end);
        let ip_total_len = payload_end - ip_offset;
        let endpoints = if matches!(self.checksum, TcpOverwriteChecksum::ComputeInSoftware) {
            Some(ipv4_addrs(self.view)?)
        } else {
            None
        };

        let buf = self
            .view
            .eth_frame_buf_mut(frame_index)
            .ok_or(TcpOverwriteError::MissingTcpHeader)?;

        buf[ip_offset + IPV4_TOTAL_LEN_OFFSET..ip_offset + IPV4_TOTAL_LEN_OFFSET + 2]
            .copy_from_slice(&u16::try_from(ip_total_len).unwrap_or(u16::MAX).to_be_bytes());
        buf[ip_offset + IPV4_FLAGS_FRAG_OFFSET..ip_offset + IPV4_FLAGS_FRAG_OFFSET + 2]
            .copy_from_slice(&[0, 0]);

        match self.checksum {
            TcpOverwriteChecksum::NicOffload => {
                buf[tcp_start + TCP_CHECKSUM_OFFSET..tcp_start + TCP_CHECKSUM_OFFSET + 2]
                    .copy_from_slice(&[0, 0]);
                if tcp_hdr.header_range.start - ip_offset >= HDR_PREFIX_LEN {
                    buf[ip_offset + IPV4_HDR_CHECKSUM_OFFSET..ip_offset + IPV4_HDR_CHECKSUM_OFFSET + 2]
                        .copy_from_slice(&[0, 0]);
                }
            }
            TcpOverwriteChecksum::ComputeInSoftware => {
                let (src_ip, dst_ip) = endpoints.expect("resolved for software checksums");
                buf[tcp_start + TCP_CHECKSUM_OFFSET..tcp_start + TCP_CHECKSUM_OFFSET + 2]
                    .copy_from_slice(&[0, 0]);
                let tcp_segment = &buf[tcp_hdr.header_range.start..payload_end];
                let checksum = compute_tcp_checksum_v4(src_ip, dst_ip, tcp_segment);
                buf[tcp_start + TCP_CHECKSUM_OFFSET..tcp_start + TCP_CHECKSUM_OFFSET + 2]
                    .copy_from_slice(&checksum);
                if tcp_hdr.header_range.start - ip_offset >= HDR_PREFIX_LEN {
                    buf[ip_offset + IPV4_HDR_CHECKSUM_OFFSET..ip_offset + IPV4_HDR_CHECKSUM_OFFSET + 2]
                        .copy_from_slice(&[0, 0]);
                    let ip_checksum =
                        compute_ipv4_header_checksum(&buf[ip_offset..ip_offset + HDR_PREFIX_LEN]);
                    buf[ip_offset + IPV4_HDR_CHECKSUM_OFFSET..ip_offset + IPV4_HDR_CHECKSUM_OFFSET + 2]
                        .copy_from_slice(&ip_checksum);
                }
            }
        }
        Ok(())
    }

    fn validate_established_data_segment(&self) -> Result<(), TcpOverwriteError> {
        let hdr = self.view.tcp_header().ok_or(TcpOverwriteError::MissingTcpHeader)?;
        if hdr.syn_flag || hdr.fin_flag || hdr.rst_flag {
            return Err(TcpOverwriteError::ControlSegmentNotEditable);
        }
        Ok(())
    }

    fn validate_writable(&self) -> Result<(), TcpOverwriteError> {
        match self.view.ip_fragment_metadata().reassembly_outcome {
            ReassemblyOutcome::AbortedRfc5722Overlap => return Err(TcpOverwriteError::ReassemblyAborted),
            ReassemblyOutcome::Incomplete => return Err(TcpOverwriteError::ReassemblyIncomplete),
            _ => {}
        }
        if self.view.tcp_header().is_none() {
            return Err(TcpOverwriteError::MissingTcpHeader);
        }
        if self.view.src_ipv4().is_none() {
            return Err(TcpOverwriteError::UnsupportedIpVersion);
        }
        Ok(())
    }

    fn header_fields(&self) -> Result<(u32, usize, bool, u32), TcpOverwriteError> {
        let hdr = self.view.tcp_header().ok_or(TcpOverwriteError::MissingTcpHeader)?;
        Ok((
            hdr.seq_num,
            self.view.payload_len(),
            hdr.ack_flag,
            hdr.ack_num,
        ))
    }

    fn is_single_part_unfragmented(&self) -> bool {
        self.view.payload_slices().len() <= 1
            && self.view.ip_fragments().len() == 1
            && !self.view.ip_fragments()[0].more_fragments
            && self.view.ip_fragments()[0].fragment_offset == 0
    }
}

impl ReceivedTcpSegmentView {
    pub fn tcp_overwriter<'a>(
        &'a mut self,
        flow: &'a mut TcpFlowState,
        direction: TcpFlowDirection,
    ) -> TcpOverwriter<'a> {
        TcpOverwriter::new(self, flow, direction)
    }
}

fn ipv4_addrs(view: &ReceivedTcpSegmentView) -> Result<(Ipv4Addr, Ipv4Addr), TcpOverwriteError> {
    match view.addrs() {
        (IpAddr::V4(s), IpAddr::V4(d)) => Ok((s, d)),
        _ => Err(TcpOverwriteError::UnsupportedIpVersion),
    }
}

fn compute_tcp_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, tcp_segment: &[u8]) -> [u8; 2] {
    let mut checksum = Checksum::new();
    checksum.add_bytes(&src.ipv4_bytes());
    checksum.add_bytes(&dst.ipv4_bytes());
    checksum.add_bytes(&[0, IpProto::Tcp.into()]);
    checksum.add_bytes(&(u16::try_from(tcp_segment.len()).unwrap_or(u16::MAX)).to_be_bytes());
    checksum.add_bytes(tcp_segment);
    checksum.checksum()
}

fn compute_ipv4_header_checksum(header_prefix: &[u8]) -> [u8; 2] {
    let mut checksum = Checksum::new();
    checksum.add_bytes(header_prefix);
    checksum.checksum()
}

/// Clears URG when the urgent pointer targets bytes removed by prefix-keep truncation.
///
/// The urgent pointer is **segment-relative** (offset from seq); it is not shifted when
/// only seq/ack are mangled. After payload truncation, clear URG if the pointer is
/// at or beyond the kept payload length.
fn adjust_urg_pointer(buf: &mut [u8], tcp_start: usize, payload_len: usize) {
    let flags = buf[tcp_start + TCP_FLAGS_OFFSET];
    if flags & TCP_FLAG_URG == 0 {
        return;
    }
    let urg_ptr = u16::from_be_bytes([
        buf[tcp_start + TCP_URG_OFFSET],
        buf[tcp_start + TCP_URG_OFFSET + 1],
    ]);
    if payload_len == 0 || usize::from(urg_ptr) >= payload_len {
        buf[tcp_start + TCP_FLAGS_OFFSET] = flags & !TCP_FLAG_URG;
        buf[tcp_start + TCP_URG_OFFSET] = 0;
        buf[tcp_start + TCP_URG_OFFSET + 1] = 0;
    }
}

/// Rewrites SACK block sequence edges using reverse-direction mangling state.
fn rewrite_sack_options(
    buf: &mut [u8],
    tcp_start: usize,
    data_offset: usize,
    flow: &TcpFlowState,
    dir: TcpFlowDirection,
) {
    if data_offset <= 20 {
        return;
    }
    let opts_start = tcp_start + 20;
    let opts_end = tcp_start + data_offset;
    if opts_end > buf.len() {
        return;
    }
    let mut i = opts_start;
    while i < opts_end {
        let kind = buf[i];
        if kind == 0 {
            break;
        }
        if kind == TCP_OPTION_KIND_NOP {
            i += 1;
            continue;
        }
        if i + 1 >= opts_end {
            break;
        }
        let len = buf[i + 1] as usize;
        if len < 2 || i + len > opts_end {
            break;
        }
        if kind == TCP_OPTION_KIND_SACK {
            let option_start = i;
            let option_end = i + len;
            let block_count = len.saturating_sub(2) / 8;
            let mut translated = alloc::vec::Vec::new();
            for block in 0..block_count {
                let off = option_start + 2 + block * 8;
                let left = u32::from_be_bytes([
                    buf[off],
                    buf[off + 1],
                    buf[off + 2],
                    buf[off + 3],
                ]);
                let right = u32::from_be_bytes([
                    buf[off + 4],
                    buf[off + 5],
                    buf[off + 6],
                    buf[off + 7],
                ]);
                if let Some(pair) = flow.translate_sack_block(dir, left, right) {
                    translated.push(pair);
                }
            }
            if translated.is_empty() {
                buf[option_start..option_end].fill(TCP_OPTION_KIND_NOP);
            } else {
                let new_len = 2 + translated.len() * 8;
                buf[option_start + 1] = u8::try_from(new_len).unwrap_or(u8::MAX);
                for (idx, (left, right)) in translated.iter().enumerate() {
                    let off = option_start + 2 + idx * 8;
                    buf[off..off + 4].copy_from_slice(&left.to_be_bytes());
                    buf[off + 4..off + 8].copy_from_slice(&right.to_be_bytes());
                }
                if new_len < len {
                    buf[option_start + new_len..option_end].fill(TCP_OPTION_KIND_NOP);
                }
            }
        }
        i += len;
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;

    use alloc::vec;
    use alloc::vec::Vec;
    use net_types::ethernet::Mac;
    use net_types::ip::Ipv4Addr;
    use netstack3_base::NetworkSerializationContext;
    use packet::{Buf, NestableSerializer as _, Serializer};
    use packet_formats::ethernet::{EtherType, ETHERNET_HDR_LEN_NO_TAG, EthernetFrameBuilder};
    use packet_formats::ip::{IpProto, Ipv4Proto};
    use packet_formats::tcp::TcpSegmentBuilder;

    use super::*;
    use crate::view::{IpFragmentInfo, IpFragmentMetadata};

    const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
    const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    const LOCAL: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
    const REMOTE: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);
    const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(100).unwrap();
    const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(200).unwrap();

    fn build_tcp_segment(payload: &[u8], seq: u32) -> ReceivedTcpSegmentView {
        let tcp = TcpSegmentBuilder::new(
            REMOTE,
            LOCAL,
            REMOTE_PORT,
            LOCAL_PORT,
            seq,
            None,
            65535,
        );
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            REMOTE,
            LOCAL,
            64,
            Ipv4Proto::Proto(IpProto::Tcp),
        );
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let frame = Buf::new(payload.to_vec(), ..)
            .wrap_in(tcp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();

        let frame_len = frame.len();
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let body_start = ip_offset + HDR_PREFIX_LEN;
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
            LOCAL.into(),
            REMOTE.into(),
        )
    }

    fn parsed_ipv4_fields(frame: &[u8]) -> (u16, bool, u16) {
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let ip_total = u16::from_be_bytes([
            frame[ip_offset + IPV4_TOTAL_LEN_OFFSET],
            frame[ip_offset + IPV4_TOTAL_LEN_OFFSET + 1],
        ]);
        let flags_frag = u16::from_be_bytes([
            frame[ip_offset + IPV4_FLAGS_FRAG_OFFSET],
            frame[ip_offset + IPV4_FLAGS_FRAG_OFFSET + 1],
        ]);
        let mf = flags_frag & 0x2000 != 0;
        let frag_off = flags_frag & 0x1FFF;
        (ip_total, mf, frag_off)
    }

    fn parsed_tcp_seq(frame: &[u8], tcp_start: usize) -> u32 {
        u32::from_be_bytes([
            frame[tcp_start + TCP_SEQ_OFFSET],
            frame[tcp_start + TCP_SEQ_OFFSET + 1],
            frame[tcp_start + TCP_SEQ_OFFSET + 2],
            frame[tcp_start + TCP_SEQ_OFFSET + 3],
        ])
    }

    fn parsed_tcp_data_offset(frame: &[u8], tcp_start: usize) -> u8 {
        (frame[tcp_start + 12] >> 4) * 4
    }

    fn parsed_tcp_ack(frame: &[u8], tcp_start: usize) -> u32 {
        u32::from_be_bytes([
            frame[tcp_start + TCP_ACK_OFFSET],
            frame[tcp_start + TCP_ACK_OFFSET + 1],
            frame[tcp_start + TCP_ACK_OFFSET + 2],
            frame[tcp_start + TCP_ACK_OFFSET + 3],
        ])
    }

    fn assert_wire_fields_and_zero_checksums(
        frame: &[u8],
        expected_ip_total: u16,
        tcp_start: usize,
    ) {
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let ip_total = u16::from_be_bytes([
            frame[ip_offset + IPV4_TOTAL_LEN_OFFSET],
            frame[ip_offset + IPV4_TOTAL_LEN_OFFSET + 1],
        ]);
        assert_eq!(ip_total, expected_ip_total, "IPv4 total length");
        assert_eq!(
            [
                frame[ip_offset + IPV4_HDR_CHECKSUM_OFFSET],
                frame[ip_offset + IPV4_HDR_CHECKSUM_OFFSET + 1],
            ],
            [0, 0],
            "IPv4 header checksum left zero for NIC offload"
        );
        assert_eq!(
            [
                frame[tcp_start + TCP_CHECKSUM_OFFSET],
                frame[tcp_start + TCP_CHECKSUM_OFFSET + 1],
            ],
            [0, 0],
            "TCP checksum left zero for NIC offload"
        );
    }

    fn build_tcp_server_segment(payload: &[u8], seq: u32, ack: u32) -> ReceivedTcpSegmentView {
        let tcp = TcpSegmentBuilder::new(
            LOCAL,
            REMOTE,
            LOCAL_PORT,
            REMOTE_PORT,
            seq,
            Some(ack),
            65535,
        );
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            LOCAL,
            REMOTE,
            64,
            Ipv4Proto::Proto(IpProto::Tcp),
        );
        let eth = EthernetFrameBuilder::new(DST_MAC, SRC_MAC, EtherType::Ipv4, 0);
        let frame = Buf::new(payload.to_vec(), ..)
            .wrap_in(tcp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();

        let frame_len = frame.len();
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let body_start = ip_offset + HDR_PREFIX_LEN;
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
            REMOTE.into(),
            LOCAL.into(),
        )
    }

    fn build_ipv4_tcp_fragment(
        fragment_offset: packet_formats::ip::FragmentOffset,
        more_fragments: bool,
        body: Vec<u8>,
        fragment_id: u16,
    ) -> Buf<Vec<u8>> {
        let mut ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            REMOTE,
            LOCAL,
            64,
            Ipv4Proto::Proto(IpProto::Tcp),
        );
        ip.id(fragment_id);
        ip.mf_flag(more_fragments);
        ip.fragment_offset(fragment_offset);
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let bytes = Buf::new(body, ..)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        Buf::new(bytes, ..)
    }

    fn deliver_fragmented_tcp(payload_len: usize, seq: u32) -> ReceivedTcpSegmentView {
        use netstack3_base::testutil::FakeDeviceId;

        use crate::context::IpsReceiveBindingsContext;
        use crate::{IpsReceiveError, IpsState, process_ethernet_frame};

        const FRAGMENT_ID: u16 = 0x00_7f;
        const FRAGMENT_BODY_LEN: usize = 104;

        let tcp = TcpSegmentBuilder::new(
            REMOTE,
            LOCAL,
            REMOTE_PORT,
            LOCAL_PORT,
            seq,
            None,
            65535,
        );
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            REMOTE,
            LOCAL,
            64,
            Ipv4Proto::Proto(IpProto::Tcp),
        );
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let frame = Buf::new(vec![0xAA; payload_len], ..)
            .wrap_in(tcp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();

        let body_start = ETHERNET_HDR_LEN_NO_TAG + HDR_PREFIX_LEN;
        let ip_body = frame[body_start..].to_vec();
        assert!(
            ip_body.len() > FRAGMENT_BODY_LEN,
            "payload must span multiple IP fragments"
        );

        let first_body = ip_body[..FRAGMENT_BODY_LEN].to_vec();
        let second_body = ip_body[FRAGMENT_BODY_LEN..].to_vec();

        let frag0 = build_ipv4_tcp_fragment(
            packet_formats::ip::FragmentOffset::ZERO,
            true,
            first_body,
            FRAGMENT_ID,
        );
        let frag1 = build_ipv4_tcp_fragment(
            packet_formats::ip::FragmentOffset::new(13).unwrap(),
            false,
            second_body,
            FRAGMENT_ID,
        );

        struct Capture {
            view: Option<ReceivedTcpSegmentView>,
        }

        impl IpsReceiveBindingsContext<FakeDeviceId> for Capture {
            fn receive_udp_datagram(
                &mut self,
                _device: &FakeDeviceId,
                _view: crate::view::ReceivedUdpDatagramView,
            ) -> Result<(), IpsReceiveError> {
                Ok(())
            }

            fn receive_tcp_segment(
                &mut self,
                _device: &FakeDeviceId,
                view: ReceivedTcpSegmentView,
            ) -> Result<(), IpsReceiveError> {
                self.view = Some(view);
                Ok(())
            }
        }

        let state = IpsState::new();
        let mut handler = Capture { view: None };
        for frame in [frag0, frag1] {
            process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).unwrap();
        }

        let view = handler.view.expect("reassembled");
        assert_eq!(view.ip_fragments().len(), 2);
        assert_eq!(
            view.ip_fragment_metadata().reassembly_outcome,
            ReassemblyOutcome::Complete
        );
        assert!(
            view.ip_fragments().iter().any(|f| f.more_fragments),
            "original segment must have MF set on at least one fragment"
        );
        view
    }

    #[test]
    fn apply_edit_backpropagates_ipv4_total_len_and_checksums() {
        const ORIGINAL_PAYLOAD: usize = 80;
        const KEEP_LEN: usize = 40;
        const EXPECTED_IP_TOTAL: u16 = 80; // 20 IPv4 + 20 TCP hdr + 40 payload

        let mut view = build_tcp_segment(&[0xAA; ORIGINAL_PAYLOAD], 1000);
        let tcp_start = view.tcp_header().unwrap().header_range.start;
        let data_offset_before = parsed_tcp_data_offset(view.eth_frames().next().unwrap(), tcp_start);

        let mut flow = TcpFlowState::default();
        view.tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .apply_edit(TcpPayloadEdit { keep_len: KEEP_LEN })
            .expect("edit");

        let frame = view.eth_frames().next().unwrap();
        let (ip_total, mf, frag_off) = parsed_ipv4_fields(frame);
        assert_eq!(ip_total, EXPECTED_IP_TOTAL, "IPv4 total length must shrink with payload");
        assert!(!mf, "MF must be clear on consolidated segment");
        assert_eq!(frag_off, 0, "IP fragment offset must be zero");
        assert_eq!(
            parsed_tcp_data_offset(frame, tcp_start),
            data_offset_before,
            "TCP data offset unchanged when only payload shrinks"
        );
        assert_eq!(
            [
                frame[tcp_start + TCP_CHECKSUM_OFFSET],
                frame[tcp_start + TCP_CHECKSUM_OFFSET + 1],
            ],
            [0, 0],
            "TCP checksum zeroed for NIC offload"
        );
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        assert_eq!(
            [
                frame[ip_offset + IPV4_HDR_CHECKSUM_OFFSET],
                frame[ip_offset + IPV4_HDR_CHECKSUM_OFFSET + 1],
            ],
            [0, 0],
            "IPv4 header checksum zeroed for NIC offload"
        );
        assert_eq!(
            frame.len(),
            ETHERNET_HDR_LEN_NO_TAG + usize::from(EXPECTED_IP_TOTAL),
            "frame buffer truncated to wire length"
        );
        assert_eq!(
            parsed_tcp_seq(frame, tcp_start),
            1000,
            "edited segment keeps original start seq"
        );
        assert_eq!(view.ip_fragments()[0].ip_packet_range.end, frame.len());
    }

    #[test]
    fn apply_edit_keeps_prefix_and_updates_delta() {
        let mut view = build_tcp_segment(&[0xAA; 80], 1000);
        let mut flow = TcpFlowState::default();
        view.tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .apply_edit(TcpPayloadEdit { keep_len: 40 })
            .expect("edit");

        assert_eq!(view.payload_len(), 40);
        assert_eq!(flow.c2s.delta, 40);
        assert_eq!(flow.c2s.committed_end, 1040);
        assert_eq!(view.payload_slices().iter().next().unwrap(), &[0xAA; 40]);
    }

    #[test]
    fn apply_edit_shrinks_unfragmented_and_zeros_checksums() {
        const ORIGINAL_PAYLOAD: usize = 64;
        const KEEP_LEN: usize = 32;
        const EXPECTED_IP_TOTAL: u16 = 72; // 20 IPv4 + 20 TCP + 32 payload

        let mut view = build_tcp_segment(&[0xAA; ORIGINAL_PAYLOAD], 1000);
        let tcp_start = view.tcp_header().unwrap().header_range.start;
        let mut flow = TcpFlowState::default();
        view.tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .apply_edit(TcpPayloadEdit { keep_len: KEEP_LEN })
            .expect("edit");

        assert_eq!(view.payload_len(), KEEP_LEN);
        let frame = view.eth_frames().next().unwrap();
        assert_wire_fields_and_zero_checksums(frame, EXPECTED_IP_TOTAL, tcp_start);

        let (ip_total, mf, frag_off) = parsed_ipv4_fields(frame);
        assert_eq!(ip_total, EXPECTED_IP_TOTAL);
        assert!(!mf);
        assert_eq!(frag_off, 0);
        assert_eq!(
            frame.len(),
            ETHERNET_HDR_LEN_NO_TAG + usize::from(EXPECTED_IP_TOTAL),
            "frame buffer truncated to wire length"
        );
        assert_eq!(view.ip_fragments()[0].ip_packet_range.end, frame.len());
    }

    #[test]
    fn apply_edit_shrinks_fragmented_tcp_to_single_fragment_clears_mf_and_total_len() {
        const ORIGINAL_PAYLOAD: usize = 200;
        const KEEP_LEN: usize = 32;
        const EXPECTED_IP_TOTAL: u16 = 72; // 20 IPv4 + 20 TCP + 32 payload

        let mut view = deliver_fragmented_tcp(ORIGINAL_PAYLOAD, 1000);
        assert_eq!(view.payload_slices().len(), 2);

        let mut flow = TcpFlowState::default();
        view.tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .apply_edit(TcpPayloadEdit { keep_len: KEEP_LEN })
            .expect("shrink fragmented segment");

        assert_eq!(view.ip_fragments().len(), 1, "must consolidate to one IP fragment");
        assert_eq!(view.eth_frames().count(), 1, "extra fragment frames must be dropped");
        assert_eq!(
            view.ip_fragment_metadata().reassembly_outcome,
            ReassemblyOutcome::NotApplicable
        );

        let frag = &view.ip_fragments()[0];
        assert!(!frag.more_fragments, "MF metadata must be cleared");
        assert_eq!(frag.fragment_offset, 0, "fragment offset must be reset");
        assert_eq!(view.payload_len(), KEEP_LEN);

        let frame = view.eth_frames().next().unwrap();
        let (ip_total, mf, frag_off) = parsed_ipv4_fields(frame);
        assert_eq!(ip_total, EXPECTED_IP_TOTAL, "IPv4 total length must match shrunk segment");
        assert!(!mf, "IPv4 MF flag must be cleared in the on-wire header");
        assert_eq!(frag_off, 0, "IPv4 fragment offset must be zero");
        let tcp_start = view.tcp_header().unwrap().header_range.start;
        assert_wire_fields_and_zero_checksums(frame, EXPECTED_IP_TOTAL, tcp_start);
        assert_eq!(
            frame.len(),
            ETHERNET_HDR_LEN_NO_TAG + usize::from(EXPECTED_IP_TOTAL),
            "consolidated frame must be truncated to wire length"
        );
    }

    #[test]
    fn apply_edit_keep_len_zero_drops_entire_payload() {
        const EXPECTED_IP_TOTAL: u16 = 40; // 20 IPv4 + 20 TCP + 0 payload

        let mut view = build_tcp_segment(&[0xAA; 64], 1000);
        let tcp_start = view.tcp_header().unwrap().header_range.start;
        let mut flow = TcpFlowState::default();
        view.tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .apply_edit(TcpPayloadEdit { keep_len: 0 })
            .expect("drop all payload");

        assert_eq!(view.payload_len(), 0);
        let frame = view.eth_frames().next().unwrap();
        assert_wire_fields_and_zero_checksums(frame, EXPECTED_IP_TOTAL, tcp_start);
        assert_eq!(
            frame.len(),
            ETHERNET_HDR_LEN_NO_TAG + usize::from(EXPECTED_IP_TOTAL),
            "frame buffer truncated to header-only segment"
        );
        assert_eq!(parsed_tcp_seq(frame, tcp_start), 1000);
    }

    #[test]
    fn apply_edit_computes_checksums_in_software() {
        use packet::ParsablePacket;
        use packet_formats::ipv4::Ipv4Packet;

        const KEEP_LEN: usize = 32;

        let mut view = build_tcp_segment(&[0xAA; 64], 1000);
        let tcp_start = view.tcp_header().unwrap().header_range.start;
        let mut flow = TcpFlowState::default();
        TcpOverwriter::with_checksum(
            &mut view,
            &mut flow,
            TcpFlowDirection::ClientToServer,
            TcpOverwriteChecksum::ComputeInSoftware,
        )
        .apply_edit(TcpPayloadEdit { keep_len: KEEP_LEN })
        .expect("edit");

        let frame = view.eth_frames().next().unwrap();
        assert_ne!(
            [
                frame[tcp_start + TCP_CHECKSUM_OFFSET],
                frame[tcp_start + TCP_CHECKSUM_OFFSET + 1],
            ],
            [0, 0],
            "TCP checksum must be computed in software mode"
        );

        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let mut ip_bytes = &frame[ip_offset..];
        Ipv4Packet::parse(&mut ip_bytes, ()).expect("IPv4 header checksum valid in software mode");
    }

    #[test]
    fn prepare_inbound_retransmit_kept_prefix_retrims_wire_fields() {
        const EXPECTED_IP_TOTAL: u16 = 80; // 20 IPv4 + 20 TCP + 40 payload

        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);

        let mut view = build_tcp_segment(&[0xBB; 80], 1000);
        let tcp_start = view.tcp_header().unwrap().header_range.start;
        let action = view
            .tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .prepare_inbound()
            .expect("retrim retransmit");

        assert_eq!(action, TcpForwardAction::Forward);
        assert_eq!(view.payload_len(), 40);
        let frame = view.eth_frames().next().unwrap();
        assert_wire_fields_and_zero_checksums(frame, EXPECTED_IP_TOTAL, tcp_start);
        assert_eq!(parsed_tcp_seq(frame, tcp_start), 1000);
    }

    #[test]
    fn prepare_inbound_new_data_mangles_seq_on_wire() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);

        let mut view = build_tcp_segment(&[0xCC; 32], 1080);
        let tcp_start = view.tcp_header().unwrap().header_range.start;
        let action = view
            .tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .prepare_inbound()
            .expect("forward new data");

        assert_eq!(action, TcpForwardAction::Forward);
        let frame = view.eth_frames().next().unwrap();
        assert_eq!(
            parsed_tcp_seq(frame, tcp_start),
            1040,
            "subsequent segment seq must reflect cumulative delta on wire"
        );
    }

    #[test]
    fn prepare_inbound_mangles_ack_on_wire_for_reverse_direction() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);

        let mut view = build_tcp_server_segment(&[], 5000, 1080);
        let tcp_start = view.tcp_header().unwrap().header_range.start;
        let action = view
            .tcp_overwriter(&mut flow, TcpFlowDirection::ServerToClient)
            .prepare_inbound()
            .expect("forward server ack");

        assert_eq!(action, TcpForwardAction::Forward);
        let frame = view.eth_frames().next().unwrap();
        assert_eq!(
            parsed_tcp_ack(frame, tcp_start),
            1040,
            "ACK must be clamped to committed_end on wire"
        );
    }

    #[test]
    fn prepare_inbound_suppresses_dropped_retransmit() {
        let mut view = build_tcp_segment(&[0xBB; 40], 1040);
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);

        let action = view
            .tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .prepare_inbound()
            .expect("classify");
        assert_eq!(action, TcpForwardAction::Suppressed);
    }

    #[test]
    fn bidirectional_ack_and_seq_after_edit() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);

        let (_, ack) = flow.translate_outbound(
            TcpFlowDirection::ServerToClient,
            5000,
            Some(1080),
            true,
        );
        assert_eq!(ack, Some(1040));

        let (seq, _) = flow.translate_outbound(
            TcpFlowDirection::ClientToServer,
            1080,
            None,
            false,
        );
        assert_eq!(seq, 1040);
    }

    fn build_syn_segment(payload: &[u8]) -> ReceivedTcpSegmentView {
        let mut tcp = TcpSegmentBuilder::new(
            REMOTE,
            LOCAL,
            REMOTE_PORT,
            LOCAL_PORT,
            1000,
            None,
            65535,
        );
        tcp.syn(true);
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            REMOTE,
            LOCAL,
            64,
            Ipv4Proto::Proto(IpProto::Tcp),
        );
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let frame = Buf::new(payload.to_vec(), ..)
            .wrap_in(tcp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();

        let frame_len = frame.len();
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let body_start = ip_offset + HDR_PREFIX_LEN;
        let tcp_hdr = crate::view::parse_tcp_header(&frame, 0, body_start).unwrap();
        assert!(tcp_hdr.syn_flag);
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
            LOCAL.into(),
            REMOTE.into(),
        )
    }

    #[test]
    fn apply_edit_rejects_syn_segment() {
        let mut view = build_syn_segment(&[0xAA; 8]);
        let mut flow = TcpFlowState::default();
        let err = view
            .tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .apply_edit(TcpPayloadEdit { keep_len: 4 })
            .expect_err("SYN must not be editable");
        assert_eq!(err, TcpOverwriteError::ControlSegmentNotEditable);
    }

    #[test]
    fn rewrite_sack_options_translates_block_edges() {
        let tcp_start = 50usize;
        let mut frame = vec![0u8; 100];
        frame[tcp_start + 12] = 0x80;
        frame[tcp_start + 13] = 0x10;
        frame[tcp_start + 20] = TCP_OPTION_KIND_SACK;
        frame[tcp_start + 21] = 10;
        frame[tcp_start + 22..tcp_start + 26].copy_from_slice(&1010u32.to_be_bytes());
        frame[tcp_start + 26..tcp_start + 30].copy_from_slice(&1040u32.to_be_bytes());

        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);
        rewrite_sack_options(&mut frame, tcp_start, 32, &flow, TcpFlowDirection::ServerToClient);

        assert_eq!(frame[tcp_start + 20], TCP_OPTION_KIND_SACK);
        assert_eq!(frame[tcp_start + 21], 10);
        assert_eq!(
            u32::from_be_bytes(frame[tcp_start + 22..tcp_start + 26].try_into().unwrap()),
            970
        );
        assert_eq!(
            u32::from_be_bytes(frame[tcp_start + 26..tcp_start + 30].try_into().unwrap()),
            1000
        );
    }

    #[test]
    fn adjust_urg_pointer_clears_urg_when_past_kept_payload() {
        let tcp_start = 50usize;
        let mut frame = vec![0u8; 80];
        frame[tcp_start + 13] = 0x30; // ACK + URG
        frame[tcp_start + 18] = 0;
        frame[tcp_start + 19] = 40; // urgent pointer at byte 40

        adjust_urg_pointer(&mut frame, tcp_start, 32);
        assert_eq!(frame[tcp_start + 13] & TCP_FLAG_URG, 0);
        assert_eq!([frame[tcp_start + 18], frame[tcp_start + 19]], [0, 0]);
    }

    #[test]
    fn adjust_urg_pointer_keeps_urg_inside_kept_prefix() {
        let tcp_start = 50usize;
        let mut frame = vec![0u8; 80];
        frame[tcp_start + 13] = 0x30;
        frame[tcp_start + 18] = 0;
        frame[tcp_start + 19] = 16;

        adjust_urg_pointer(&mut frame, tcp_start, 32);
        assert_ne!(frame[tcp_start + 13] & TCP_FLAG_URG, 0);
        assert_eq!([frame[tcp_start + 18], frame[tcp_start + 19]], [0, 16]);
    }

    #[test]
    fn apply_edit_clears_urg_when_pointer_in_dropped_tail() {
        let mut view = build_tcp_segment(&[0xAA; 64], 1000);
        let tcp_start = view.tcp_header().unwrap().header_range.start;
        if let Some(buf) = view.eth_frame_buf_mut(0) {
            buf[tcp_start + 13] |= TCP_FLAG_URG;
            buf[tcp_start + 18] = 0;
            buf[tcp_start + 19] = 48;
        }

        let mut flow = TcpFlowState::default();
        view.tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .apply_edit(TcpPayloadEdit { keep_len: 32 })
            .expect("edit");

        let frame = view.eth_frames().next().unwrap();
        assert_eq!(frame[tcp_start + 13] & TCP_FLAG_URG, 0);
    }

    #[test]
    fn prepare_inbound_notes_fin_for_flow_teardown() {
        let mut tcp = TcpSegmentBuilder::new(
            REMOTE,
            LOCAL,
            REMOTE_PORT,
            LOCAL_PORT,
            1000,
            None,
            65535,
        );
        tcp.fin(true);
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            REMOTE,
            LOCAL,
            64,
            Ipv4Proto::Proto(IpProto::Tcp),
        );
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let frame = Buf::new(vec![0u8; 0], ..)
            .wrap_in(tcp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();

        let frame_len = frame.len();
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let body_start = ip_offset + HDR_PREFIX_LEN;
        let tcp_hdr = crate::view::parse_tcp_header(&frame, 0, body_start).unwrap();
        let payload_start = tcp_hdr.header_range.end;
        let mut view = ReceivedTcpSegmentView::new(
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
            LOCAL.into(),
            REMOTE.into(),
        );

        let mut flow = TcpFlowState::default();
        view.tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .prepare_inbound()
            .expect("forward FIN");
        assert!(flow.fin_c2s);
        assert!(!flow.should_evict());
    }

    #[test]
    fn e2e_fragmented_tcp_apply_edit_then_server_ack_mangled_on_wire() {
        const KEEP_LEN: usize = 160;
        const ORIGINAL_PAYLOAD: usize = 200;

        let mut view = deliver_fragmented_tcp(ORIGINAL_PAYLOAD, 1000);
        let mut flow = TcpFlowState::default();
        view.tcp_overwriter(&mut flow, TcpFlowDirection::ClientToServer)
            .apply_edit(TcpPayloadEdit { keep_len: KEEP_LEN })
            .expect("fragmented edit");

        let mut server_view = build_tcp_server_segment(&[], 5000, 1080);
        let tcp_start = server_view.tcp_header().unwrap().header_range.start;
        let action = server_view
            .tcp_overwriter(&mut flow, TcpFlowDirection::ServerToClient)
            .prepare_inbound()
            .expect("server prepare");
        assert_eq!(action, TcpForwardAction::Forward);

        let frame = server_view.eth_frames().next().unwrap();
        assert_eq!(parsed_tcp_ack(frame, tcp_start), 1040);
    }
}
