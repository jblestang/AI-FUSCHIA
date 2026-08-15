// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! In-place UDP payload overwrite with IPv4/UDP checksum and length updates.

use alloc::vec::Vec;

use internet_checksum::Checksum;
use net_types::ip::{IpAddr, Ipv4Addr};
use packet_formats::ip::IpProto;
use packet_formats::ipv4::HDR_PREFIX_LEN;
use packet_formats::udp::HEADER_BYTES;

use crate::view::{
    IpFragmentInfo, ReceivedUdpDatagramView, ReassemblyOutcome, UdpHeaderView,
};

const IPV4_TOTAL_LEN_OFFSET: usize = 2;
const IPV4_FLAGS_FRAG_OFFSET: usize = 6;
const IPV4_HDR_CHECKSUM_OFFSET: usize = 10;
const UDP_LENGTH_OFFSET: usize = 4;
const UDP_CHECKSUM_OFFSET: usize = 6;

/// Errors from [`UdpOverwriter`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpOverwriteError {
    /// Reassembly was aborted (e.g. RFC 5722 overlap); payload is not writable.
    ReassemblyAborted,
    /// Reassembly is incomplete; no full datagram is available yet.
    ReassemblyIncomplete,
    /// The view has no parsed UDP header.
    MissingUdpHeader,
    /// Only IPv4 is supported for in-place overwrite today.
    UnsupportedIpVersion,
    /// In-place overwrite requires equal old and new payload lengths.
    PayloadLengthMismatch {
        /// Current payload length in bytes.
        expected: usize,
        /// Provided replacement length in bytes.
        got: usize,
    },
    /// The backing frame buffer cannot grow to fit the new datagram.
    BufferTooSmall {
        /// Bytes required for the consolidated frame.
        needed: usize,
        /// Bytes available without reallocation headroom.
        available: usize,
    },
}

/// Mutates a delivered [`ReceivedUdpDatagramView`] UDP payload in place.
///
/// After L7 deep inspection, use this to replace payload bytes, refresh the UDP
/// and IPv4 header length fields, and recompute checksums on the backing frame
/// buffers.
pub struct UdpOverwriter<'a> {
    view: &'a mut ReceivedUdpDatagramView,
}

impl<'a> UdpOverwriter<'a> {
    /// Creates an overwriter for `view`.
    pub fn new(view: &'a mut ReceivedUdpDatagramView) -> Self {
        Self { view }
    }

    /// Current UDP payload length in bytes.
    pub fn payload_len(&self) -> Result<usize, UdpOverwriteError> {
        self.validate_writable()?;
        Ok(self.current_payload_len())
    }

    /// Replaces the UDP payload, updating UDP/IPv4 lengths and checksums.
    ///
    /// Fragmented datagrams are consolidated into a single Ethernet frame when
    /// the payload length changes. Same-length fragmented payloads are patched
    /// across existing slice parts without consolidation.
    pub fn overwrite_payload(&mut self, new_payload: &[u8]) -> Result<(), UdpOverwriteError> {
        self.validate_writable()?;
        let current = self.current_payload_len();
        if current == new_payload.len() && self.is_single_part_unfragmented() {
            self.overwrite_single_frame(new_payload)?;
        } else if current == new_payload.len() {
            self.overwrite_payload_parts(new_payload)?;
            self.refresh_udp_checksum_only(new_payload.len())?;
        } else {
            self.consolidate_and_write(new_payload)?;
        }
        Ok(())
    }

    /// Overwrites payload bytes without changing length (patch-in-place).
    pub fn overwrite_payload_in_place(&mut self, new_payload: &[u8]) -> Result<(), UdpOverwriteError> {
        self.validate_writable()?;
        let current = self.current_payload_len();
        if current != new_payload.len() {
            return Err(UdpOverwriteError::PayloadLengthMismatch { expected: current, got: new_payload.len() });
        }
        if self.is_single_part_unfragmented() {
            self.overwrite_single_frame(new_payload)?;
        } else {
            self.overwrite_payload_parts(new_payload)?;
            self.refresh_udp_checksum_only(new_payload.len())?;
        }
        Ok(())
    }

    fn validate_writable(&self) -> Result<(), UdpOverwriteError> {
        match self.view.ip_fragment_metadata().reassembly_outcome {
            ReassemblyOutcome::AbortedRfc5722Overlap => return Err(UdpOverwriteError::ReassemblyAborted),
            ReassemblyOutcome::Incomplete => return Err(UdpOverwriteError::ReassemblyIncomplete),
            _ => {}
        }
        if self.view.udp_header().is_none() {
            return Err(UdpOverwriteError::MissingUdpHeader);
        }
        if self.view.src_ipv4().is_none() {
            return Err(UdpOverwriteError::UnsupportedIpVersion);
        }
        Ok(())
    }

    fn current_payload_len(&self) -> usize {
        self.view.payload_slices().iter().map(|s| s.len()).sum()
    }

    fn is_single_part_unfragmented(&self) -> bool {
        self.view.payload_slices().len() == 1
            && self.view.ip_fragments().len() == 1
            && !self.view.ip_fragments()[0].more_fragments
            && self.view.ip_fragments()[0].fragment_offset == 0
    }

    fn overwrite_payload_parts(&mut self, new_payload: &[u8]) -> Result<(), UdpOverwriteError> {
        let mut offset = 0;
        let part_count = self.view.payload_slices().len();
        for i in 0..part_count {
            let len = self.view.payload_slices().iter().nth(i).map(|s| s.len()).unwrap_or(0);
            if !self.view.write_payload_part(i, &new_payload[offset..offset + len]) {
                return Err(UdpOverwriteError::PayloadLengthMismatch {
                    expected: self.current_payload_len(),
                    got: new_payload.len(),
                });
            }
            offset += len;
        }
        Ok(())
    }

    fn overwrite_single_frame(&mut self, new_payload: &[u8]) -> Result<(), UdpOverwriteError> {
        let udp_hdr = self.view.udp_header().expect("validated").clone();
        let frag = self.view.ip_fragments().first().expect("single fragment");
        let frame_index = frag.eth_frame_index;
        let ip_start = frag.ip_packet_range.start;
        let payload_start = udp_hdr.header_range.end;
        let payload_end = payload_start + new_payload.len();

        if !self.view.ensure_eth_frame_len(frame_index, payload_end) {
            return Err(UdpOverwriteError::MissingUdpHeader);
        }
        {
            let buf = self
                .view
                .eth_frame_buf_mut(frame_index)
                .ok_or(UdpOverwriteError::MissingUdpHeader)?;
            buf[payload_start..payload_end].copy_from_slice(new_payload);
        }

        self.patch_unfragmented_lengths_and_checksums(frame_index, ip_start, payload_end)
    }

    fn refresh_udp_checksum_only(&mut self, payload_len: usize) -> Result<(), UdpOverwriteError> {
        let (src_ip, dst_ip) = ipv4_addrs(self.view)?;
        let udp_hdr = self.view.udp_header().expect("validated").clone();
        let udp_len = HEADER_BYTES + payload_len;
        self.view.update_udp_header_view(u16::try_from(udp_len).unwrap_or(u16::MAX));

        let header = self
            .view
            .eth_frame_buf(udp_hdr.eth_frame_index)
            .and_then(|f| f.get(udp_hdr.header_range.clone()))
            .ok_or(UdpOverwriteError::MissingUdpHeader)?
            .to_vec();

        let mut header = header;
        header[UDP_LENGTH_OFFSET..UDP_LENGTH_OFFSET + 2]
            .copy_from_slice(&u16::try_from(udp_len).unwrap_or(u16::MAX).to_be_bytes());
        header[UDP_CHECKSUM_OFFSET..UDP_CHECKSUM_OFFSET + 2].copy_from_slice(&[0, 0]);

        let payload_parts: Vec<&[u8]> = self.view.payload_slices().iter().collect();
        let checksum = compute_udp_checksum_v4_parts(src_ip, dst_ip, &header, payload_parts.iter().copied());

        let buf = self
            .view
            .eth_frame_buf_mut(udp_hdr.eth_frame_index)
            .ok_or(UdpOverwriteError::MissingUdpHeader)?;
        buf[udp_hdr.header_range.start + UDP_LENGTH_OFFSET..udp_hdr.header_range.start + UDP_LENGTH_OFFSET + 2]
            .copy_from_slice(&u16::try_from(udp_len).unwrap_or(u16::MAX).to_be_bytes());
        buf[udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET..udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET + 2]
            .copy_from_slice(&checksum);
        Ok(())
    }

    fn consolidate_and_write(&mut self, new_payload: &[u8]) -> Result<(), UdpOverwriteError> {
        let first_frag = self.view.ip_fragments().first().expect("fragment").clone();
        let udp_hdr = self.view.udp_header().expect("validated").clone();
        let ip_offset = first_frag.ip_packet_range.start;
        let ip_hdr_len = first_frag.ip_body_range.start - ip_offset;
        let payload_start = first_frag.ip_body_range.start + HEADER_BYTES;
        let payload_end = payload_start + new_payload.len();

        let frame_len = ip_offset + ip_hdr_len + HEADER_BYTES + new_payload.len();
        if !self.view.ensure_eth_frame_len(first_frag.eth_frame_index, frame_len) {
            return Err(UdpOverwriteError::MissingUdpHeader);
        }
        {
            let buf = self
                .view
                .eth_frame_buf_mut(first_frag.eth_frame_index)
                .ok_or(UdpOverwriteError::MissingUdpHeader)?;
            buf[payload_start..payload_end].copy_from_slice(new_payload);
        }

        self.patch_unfragmented_lengths_and_checksums(
            first_frag.eth_frame_index,
            ip_offset,
            payload_end,
        )?;

        let frame_bytes = self
            .view
            .eth_frame_buf(first_frag.eth_frame_index)
            .expect("frame")
            .to_vec();
        let frame_len = ip_offset + ip_hdr_len + HEADER_BYTES + new_payload.len();

        let updated_udp = UdpHeaderView {
            length: u16::try_from(HEADER_BYTES + new_payload.len()).unwrap_or(u16::MAX),
            header_range: first_frag.ip_body_range.start..payload_start,
            ..udp_hdr
        };

        let ip_fragment = IpFragmentInfo {
            eth_frame_index: 0,
            ip_packet_range: ip_offset..frame_len,
            identification: first_frag.identification,
            fragment_offset: 0,
            more_fragments: false,
            ip_body_range: (ip_offset + ip_hdr_len)..frame_len,
        };

        self.view.apply_unfragmented_overwrite(
            alloc::vec![packet::Buf::new(frame_bytes, ..)],
            ip_fragment,
            updated_udp,
            payload_start..payload_end,
        );
        Ok(())
    }

    fn patch_unfragmented_lengths_and_checksums(
        &mut self,
        frame_index: usize,
        ip_offset: usize,
        payload_end: usize,
    ) -> Result<(), UdpOverwriteError> {
        let (src_ip, dst_ip) = ipv4_addrs(self.view)?;
        let udp_hdr = self.view.udp_header().expect("validated").clone();
        let ip_body_start = udp_hdr.header_range.start;
        let udp_len = payload_end - ip_body_start;
        let ip_total_len = payload_end - ip_offset;

        let buf = self
            .view
            .eth_frame_buf_mut(frame_index)
            .ok_or(UdpOverwriteError::MissingUdpHeader)?;

        buf[udp_hdr.header_range.start + UDP_LENGTH_OFFSET..udp_hdr.header_range.start + UDP_LENGTH_OFFSET + 2]
            .copy_from_slice(&u16::try_from(udp_len).unwrap_or(u16::MAX).to_be_bytes());
        buf[ip_offset + IPV4_TOTAL_LEN_OFFSET..ip_offset + IPV4_TOTAL_LEN_OFFSET + 2]
            .copy_from_slice(&u16::try_from(ip_total_len).unwrap_or(u16::MAX).to_be_bytes());
        buf[ip_offset + IPV4_FLAGS_FRAG_OFFSET..ip_offset + IPV4_FLAGS_FRAG_OFFSET + 2].copy_from_slice(&[0, 0]);

        buf[udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET..udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET + 2]
            .copy_from_slice(&[0, 0]);
        let udp_checksum = compute_udp_checksum_v4(src_ip, dst_ip, &buf[ip_body_start..payload_end]);
        buf[udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET..udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET + 2]
            .copy_from_slice(&udp_checksum);

        if ip_body_start - ip_offset >= HDR_PREFIX_LEN {
            buf[ip_offset + IPV4_HDR_CHECKSUM_OFFSET..ip_offset + IPV4_HDR_CHECKSUM_OFFSET + 2]
                .copy_from_slice(&[0, 0]);
            let ip_checksum = compute_ipv4_header_checksum(&buf[ip_offset..ip_offset + HDR_PREFIX_LEN]);
            buf[ip_offset + IPV4_HDR_CHECKSUM_OFFSET..ip_offset + IPV4_HDR_CHECKSUM_OFFSET + 2]
                .copy_from_slice(&ip_checksum);
        }

        self.view.update_udp_header_view(u16::try_from(udp_len).unwrap_or(u16::MAX));
        Ok(())
    }
}

impl ReceivedUdpDatagramView {
    /// Returns a [`UdpOverwriter`] for this datagram.
    pub fn udp_overwriter(&mut self) -> UdpOverwriter<'_> {
        UdpOverwriter::new(self)
    }
}

fn ipv4_addrs(view: &ReceivedUdpDatagramView) -> Result<(Ipv4Addr, Ipv4Addr), UdpOverwriteError> {
    match view.addrs() {
        (IpAddr::V4(s), IpAddr::V4(d)) => Ok((s, d)),
        _ => Err(UdpOverwriteError::UnsupportedIpVersion),
    }
}

fn compute_udp_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, udp_segment: &[u8]) -> [u8; 2] {
    let mut checksum = Checksum::new();
    checksum.add_bytes(&src.ipv4_bytes());
    checksum.add_bytes(&dst.ipv4_bytes());
    checksum.add_bytes(&[0, IpProto::Udp.into()]);
    checksum.add_bytes(&(u16::try_from(udp_segment.len()).unwrap_or(u16::MAX)).to_be_bytes());
    checksum.add_bytes(udp_segment);
    checksum.checksum()
}

fn compute_udp_checksum_v4_parts<'a>(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    udp_header: &[u8],
    payload_parts: impl IntoIterator<Item = &'a [u8]>,
) -> [u8; 2] {
    let payload_parts: Vec<&[u8]> = payload_parts.into_iter().collect();
    let udp_len = udp_header.len() + payload_parts.iter().map(|p| p.len()).sum::<usize>();
    let mut checksum = Checksum::new();
    checksum.add_bytes(&src.ipv4_bytes());
    checksum.add_bytes(&dst.ipv4_bytes());
    checksum.add_bytes(&[0, IpProto::Udp.into()]);
    checksum.add_bytes(&(u16::try_from(udp_len).unwrap_or(u16::MAX)).to_be_bytes());
    checksum.add_bytes(udp_header);
    for part in payload_parts {
        checksum.add_bytes(part);
    }
    checksum.checksum()
}

fn compute_ipv4_header_checksum(header_prefix: &[u8]) -> [u8; 2] {
    let mut checksum = Checksum::new();
    checksum.add_bytes(header_prefix);
    checksum.checksum()
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;

    use alloc::vec;
    use alloc::vec::Vec;

    use net_types::ethernet::Mac;
    use netstack3_base::NetworkSerializationContext;
    use packet::{Buf, NestableSerializer as _, ParsablePacket, Serializer};
    use packet_formats::ethernet::{EtherType, ETHERNET_HDR_LEN_NO_TAG, EthernetFrameBuilder};
    use packet_formats::ip::Ipv4Proto;
    use packet_formats::ipv4::Ipv4Packet;
    use packet_formats::udp::UdpPacketBuilder;

    use super::*;
    use crate::view::IpFragmentMetadata;

    const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
    const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    const LOCAL: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
    const REMOTE: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);
    const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(100).unwrap();
    const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(200).unwrap();

    fn build_unfragmented_udp(payload: &[u8]) -> ReceivedUdpDatagramView {
        let udp = UdpPacketBuilder::new(REMOTE, LOCAL, Some(REMOTE_PORT), LOCAL_PORT);
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            REMOTE,
            LOCAL,
            64,
            Ipv4Proto::Proto(IpProto::Udp),
        );
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let frame = Buf::new(payload.to_vec(), ..)
            .wrap_in(udp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();

        let frame_len = frame.len();
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let body_start = ip_offset + HDR_PREFIX_LEN;
        let payload_start = body_start + HEADER_BYTES;
        ReceivedUdpDatagramView::new(
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
            Some(UdpHeaderView {
                src_port: REMOTE_PORT.get(),
                dst_port: LOCAL_PORT.get(),
                length: u16::try_from(HEADER_BYTES + payload.len()).unwrap(),
                eth_frame_index: 0,
                header_range: body_start..payload_start,
            }),
            alloc::vec![(0, payload_start..frame_len)],
            LOCAL.into(),
            REMOTE.into(),
        )
    }

    fn frame_parseable(frame: &[u8]) -> bool {
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let mut ip_bytes = &frame[ip_offset..];
        Ipv4Packet::parse(&mut ip_bytes, ()).is_ok()
    }

    fn build_ipv4_udp_fragment(
        fragment_offset: packet_formats::ip::FragmentOffset,
        more_fragments: bool,
        body: Vec<u8>,
        fragment_id: u16,
    ) -> Buf<Vec<u8>> {
        let mut ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            REMOTE,
            LOCAL,
            64,
            Ipv4Proto::Proto(IpProto::Udp),
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

    fn deliver_fragmented_udp(payload_len: usize) -> ReceivedUdpDatagramView {
        use netstack3_base::testutil::FakeDeviceId;

        use crate::context::IpsReceiveBindingsContext;
        use crate::{IpsReceiveError, IpsState, process_ethernet_frame};

        const FRAGMENT_ID: u16 = 0x00_7e;
        const FRAGMENT_BODY_LEN: usize = 104;
        let udp_total = HEADER_BYTES + payload_len;

        let mut first_body = vec![
            (REMOTE_PORT.get() >> 8) as u8,
            (REMOTE_PORT.get() & 0xff) as u8,
            (LOCAL_PORT.get() >> 8) as u8,
            (LOCAL_PORT.get() & 0xff) as u8,
            (udp_total >> 8) as u8,
            (udp_total & 0xff) as u8,
            0x00,
            0x00,
        ];
        first_body.resize(FRAGMENT_BODY_LEN, 0xAA);

        let second_len = udp_total - FRAGMENT_BODY_LEN;
        let second_body = vec![0xBB; second_len];

        let frag0 = build_ipv4_udp_fragment(
            packet_formats::ip::FragmentOffset::ZERO,
            true,
            first_body,
            FRAGMENT_ID,
        );
        let frag1 = build_ipv4_udp_fragment(
            packet_formats::ip::FragmentOffset::new(13).unwrap(),
            false,
            second_body,
            FRAGMENT_ID,
        );

        struct Capture {
            view: Option<ReceivedUdpDatagramView>,
        }

        impl IpsReceiveBindingsContext<FakeDeviceId> for Capture {
            fn receive_udp_datagram(
                &mut self,
                _device: &FakeDeviceId,
                view: ReceivedUdpDatagramView,
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
            "original datagram must have MF set on at least one fragment"
        );
        view
    }

    fn parsed_ipv4_fields(frame: &[u8]) -> (u16, bool, u16) {
        use packet_formats::ipv4::Ipv4Header;

        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let mut ip_bytes = &frame[ip_offset..];
        let packet = Ipv4Packet::parse(&mut ip_bytes, ()).expect("parse ipv4");
        let ip_total = u16::from_be_bytes([
            frame[ip_offset + IPV4_TOTAL_LEN_OFFSET],
            frame[ip_offset + IPV4_TOTAL_LEN_OFFSET + 1],
        ]);
        (
            ip_total,
            packet.mf_flag(),
            packet.fragment_offset().into_raw(),
        )
    }

    #[test]
    fn overwrite_shrinks_fragmented_udp_to_single_fragment_clears_mf_and_total_len() {
        const ORIGINAL_PAYLOAD: usize = 200;
        const NEW_PAYLOAD: usize = 32;
        const EXPECTED_UDP_LEN: u16 = 40; // 8 + 32
        const EXPECTED_IP_TOTAL: u16 = 60; // 20 + 8 + 32

        let mut view = deliver_fragmented_udp(ORIGINAL_PAYLOAD);
        assert_eq!(view.payload_slices().len(), 2);

        view.udp_overwriter()
            .overwrite_payload(&[0xCC; NEW_PAYLOAD])
            .expect("shrink fragmented datagram");

        assert_eq!(view.ip_fragments().len(), 1, "must consolidate to one IP fragment");
        assert_eq!(view.eth_frames().count(), 1, "extra fragment frames must be dropped");
        assert_eq!(
            view.ip_fragment_metadata().reassembly_outcome,
            ReassemblyOutcome::NotApplicable
        );

        let frag = &view.ip_fragments()[0];
        assert!(!frag.more_fragments, "MF metadata must be cleared");
        assert_eq!(frag.fragment_offset, 0, "fragment offset must be reset");

        assert_eq!(view.udp_header().unwrap().length, EXPECTED_UDP_LEN);
        assert_eq!(view.payload_slices().iter().map(|s| s.len()).sum::<usize>(), NEW_PAYLOAD);

        let frame = view.eth_frames().next().unwrap();
        let (ip_total, mf, frag_off) = parsed_ipv4_fields(frame);
        assert_eq!(ip_total, EXPECTED_IP_TOTAL, "IPv4 total length must match shrunk datagram");
        assert!(!mf, "IPv4 MF flag must be cleared in the on-wire header");
        assert_eq!(frag_off, 0, "IPv4 fragment offset must be zero");
        assert!(frame_parseable(frame));
    }

    #[test]
    fn overwrite_shrinks_payload_and_updates_checksums() {
        let mut view = build_unfragmented_udp(&[0xAA; 64]);
        view.udp_overwriter()
            .overwrite_payload(&[0xBB; 32])
            .expect("overwrite");

        assert_eq!(view.payload_slices().iter().map(|s| s.len()).sum::<usize>(), 32);
        assert_eq!(view.udp_header().unwrap().length, 40);
        let frame = view.eth_frames().next().unwrap();
        assert!(frame_parseable(frame));
        assert_eq!(view.payload_slices().iter().next().unwrap(), &[0xBB; 32]);

        let (ip_total, mf, frag_off) = parsed_ipv4_fields(frame);
        assert_eq!(ip_total, 60);
        assert!(!mf);
        assert_eq!(frag_off, 0);
    }

    #[test]
    fn overwrite_in_place_same_length() {
        let mut view = build_unfragmented_udp(&[0x01, 0x02, 0x03, 0x04]);
        view.udp_overwriter()
            .overwrite_payload_in_place(&[0x10, 0x20, 0x30, 0x40])
            .expect("in-place");

        assert_eq!(
            view.payload_slices().iter().next().unwrap(),
            &[0x10, 0x20, 0x30, 0x40][..]
        );
    }
}
