// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! In-place UDP payload overwrite with IPv4/UDP length updates.
//!
//! Checksum handling is configurable via [`UdpOverwriteChecksum`]: leave fields
//! zero for NIC offload, or recompute in software.

use alloc::vec::Vec;

use internet_checksum::Checksum;
use net_types::ip::{IpAddr, Ipv4Addr};
use packet_formats::ip::IpProto;
use packet_formats::ipv4::HDR_PREFIX_LEN;
use packet_formats::udp::HEADER_BYTES;

use crate::view::{
    IpFragmentInfo, ReceivedUdpDatagramView, ReassemblyOutcome, UdpHeaderView,
};
use crate::wire::{
    IPV4_FLAGS_FRAG_OFFSET, IPV4_HDR_CHECKSUM_OFFSET, IPV4_TOTAL_LEN_OFFSET, UDP_CHECKSUM_OFFSET,
    UDP_LENGTH_OFFSET,
};

/// How [`UdpOverwriter`] updates IPv4/UDP checksum fields after a rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UdpOverwriteChecksum {
    /// Leave checksum fields at zero for NIC/hardware offload on egress.
    #[default]
    NicOffload,
    /// Recompute UDP and IPv4 header checksums in software.
    ComputeInSoftware,
}

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
/// After L7 deep inspection, use this to replace payload bytes and refresh UDP
/// and IPv4 header length fields. Checksum handling is selected via
/// [`UdpOverwriteChecksum`] ([`UdpOverwriteChecksum::NicOffload`] by default).
pub struct UdpOverwriter<'a> {
    view: &'a mut ReceivedUdpDatagramView,
    checksum: UdpOverwriteChecksum,
}

impl<'a> UdpOverwriter<'a> {
    /// Creates an overwriter using [`UdpOverwriteChecksum::NicOffload`].
    pub fn new(view: &'a mut ReceivedUdpDatagramView) -> Self {
        Self::with_checksum(view, UdpOverwriteChecksum::default())
    }

    /// Creates an overwriter with explicit checksum handling.
    pub fn with_checksum(view: &'a mut ReceivedUdpDatagramView, checksum: UdpOverwriteChecksum) -> Self {
        Self { view, checksum }
    }

    /// Checksum mode for this overwriter.
    pub fn checksum_mode(&self) -> UdpOverwriteChecksum {
        self.checksum
    }

    /// Current UDP payload length in bytes.
    pub fn payload_len(&self) -> Result<usize, UdpOverwriteError> {
        self.validate_writable()?;
        Ok(self.current_payload_len())
    }

    /// Replaces the UDP payload, updating UDP/IPv4 lengths and checksums per
    /// [`Self::checksum_mode`].
    ///
    /// Single-frame datagrams are patched in place (like
    /// [`Self::overwrite_payload_in_place`]) with metadata and buffer truncation
    /// updated to the new wire length. Multi-frame datagrams that shrink to one
    /// frame write only into the first backing buffer, drop surplus frames, and
    /// truncate to the bytes needed on the wire.
    pub fn overwrite_payload(&mut self, new_payload: &[u8]) -> Result<(), UdpOverwriteError> {
        self.validate_writable()?;
        let current = self.current_payload_len();
        if current == new_payload.len() && self.is_single_part_unfragmented() {
            self.overwrite_single_frame(new_payload)?;
        } else if current == new_payload.len() {
            self.overwrite_payload_parts(new_payload)?;
            self.refresh_udp_header_fields(new_payload.len())?;
        } else if self.is_single_part_unfragmented() {
            self.overwrite_single_frame(new_payload)?;
            self.commit_single_frame_length_change(new_payload.len())?;
        } else {
            self.shrink_to_single_frame(new_payload)?;
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
            self.refresh_udp_header_fields(new_payload.len())?;
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

        self.patch_unfragmented_lengths(frame_index, ip_start, payload_end)
    }

    fn refresh_udp_header_fields(&mut self, payload_len: usize) -> Result<(), UdpOverwriteError> {
        let udp_hdr = self.view.udp_header().expect("validated").clone();
        let udp_len = HEADER_BYTES + payload_len;
        self.view.update_udp_header_view(u16::try_from(udp_len).unwrap_or(u16::MAX));

        match self.checksum {
            UdpOverwriteChecksum::NicOffload => {
                let buf = self
                    .view
                    .eth_frame_buf_mut(udp_hdr.eth_frame_index)
                    .ok_or(UdpOverwriteError::MissingUdpHeader)?;
                buf[udp_hdr.header_range.start + UDP_LENGTH_OFFSET
                    ..udp_hdr.header_range.start + UDP_LENGTH_OFFSET + 2]
                    .copy_from_slice(&u16::try_from(udp_len).unwrap_or(u16::MAX).to_be_bytes());
                buf[udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET
                    ..udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET + 2]
                    .copy_from_slice(&[0, 0]);
            }
            UdpOverwriteChecksum::ComputeInSoftware => {
                let (src_ip, dst_ip) = ipv4_addrs(self.view)?;
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
                let checksum = compute_udp_checksum_v4_parts(
                    src_ip,
                    dst_ip,
                    &header,
                    payload_parts.iter().copied(),
                );

                let buf = self
                    .view
                    .eth_frame_buf_mut(udp_hdr.eth_frame_index)
                    .ok_or(UdpOverwriteError::MissingUdpHeader)?;
                buf[udp_hdr.header_range.start + UDP_LENGTH_OFFSET
                    ..udp_hdr.header_range.start + UDP_LENGTH_OFFSET + 2]
                    .copy_from_slice(&u16::try_from(udp_len).unwrap_or(u16::MAX).to_be_bytes());
                buf[udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET
                    ..udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET + 2]
                    .copy_from_slice(&checksum);
            }
        }
        Ok(())
    }

    fn commit_single_frame_length_change(&mut self, new_payload_len: usize) -> Result<(), UdpOverwriteError> {
        let frag = self.view.ip_fragments().first().expect("fragment").clone();
        let udp_hdr = self.view.udp_header().expect("validated");
        let ip_offset = frag.ip_packet_range.start;
        let ip_body_start = udp_hdr.header_range.start;
        let payload_start = udp_hdr.header_range.end;
        let payload_end = payload_start + new_payload_len;
        let wire_len = payload_end;

        self.view.truncate_eth_frame(frag.eth_frame_index, wire_len);
        self.view.apply_single_frame_length_change(
            frag.eth_frame_index,
            ip_offset..payload_end,
            ip_body_start..payload_end,
            payload_start..payload_end,
            u16::try_from(HEADER_BYTES + new_payload_len).unwrap_or(u16::MAX),
        );
        Ok(())
    }

    fn shrink_to_single_frame(&mut self, new_payload: &[u8]) -> Result<(), UdpOverwriteError> {
        let first_frag = self.view.ip_fragments().first().expect("fragment").clone();
        let ip_offset = first_frag.ip_packet_range.start;
        let ip_hdr_len = first_frag.ip_body_range.start - ip_offset;
        let payload_start = first_frag.ip_body_range.start + HEADER_BYTES;
        let payload_end = payload_start + new_payload.len();
        let frame_index = first_frag.eth_frame_index;

        let wire_len = ip_offset + ip_hdr_len + HEADER_BYTES + new_payload.len();
        if !self.view.ensure_eth_frame_len(frame_index, wire_len) {
            return Err(UdpOverwriteError::MissingUdpHeader);
        }
        {
            let buf = self
                .view
                .eth_frame_buf_mut(frame_index)
                .ok_or(UdpOverwriteError::MissingUdpHeader)?;
            buf[payload_start..payload_end].copy_from_slice(new_payload);
        }

        self.patch_unfragmented_lengths(frame_index, ip_offset, payload_end)?;

        self.view.truncate_eth_frame(frame_index, payload_end);
        self.view.retain_eth_frames_through(frame_index);
        self.view.apply_single_frame_length_change(
            frame_index,
            ip_offset..payload_end,
            (ip_offset + ip_hdr_len)..payload_end,
            payload_start..payload_end,
            u16::try_from(HEADER_BYTES + new_payload.len()).unwrap_or(u16::MAX),
        );
        Ok(())
    }

    fn patch_unfragmented_lengths(
        &mut self,
        frame_index: usize,
        ip_offset: usize,
        payload_end: usize,
    ) -> Result<(), UdpOverwriteError> {
        let udp_hdr = self.view.udp_header().expect("validated").clone();
        let ip_body_start = udp_hdr.header_range.start;
        let udp_len = payload_end - ip_body_start;
        let ip_total_len = payload_end - ip_offset;
        let ipv4_endpoints = match self.checksum {
            UdpOverwriteChecksum::ComputeInSoftware => Some(ipv4_addrs(self.view)?),
            UdpOverwriteChecksum::NicOffload => None,
        };

        let buf = self
            .view
            .eth_frame_buf_mut(frame_index)
            .ok_or(UdpOverwriteError::MissingUdpHeader)?;

        buf[udp_hdr.header_range.start + UDP_LENGTH_OFFSET..udp_hdr.header_range.start + UDP_LENGTH_OFFSET + 2]
            .copy_from_slice(&u16::try_from(udp_len).unwrap_or(u16::MAX).to_be_bytes());
        buf[ip_offset + IPV4_TOTAL_LEN_OFFSET..ip_offset + IPV4_TOTAL_LEN_OFFSET + 2]
            .copy_from_slice(&u16::try_from(ip_total_len).unwrap_or(u16::MAX).to_be_bytes());
        buf[ip_offset + IPV4_FLAGS_FRAG_OFFSET..ip_offset + IPV4_FLAGS_FRAG_OFFSET + 2].copy_from_slice(&[0, 0]);

        match self.checksum {
            UdpOverwriteChecksum::NicOffload => {
                buf[udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET
                    ..udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET + 2]
                    .copy_from_slice(&[0, 0]);
                if ip_body_start - ip_offset >= HDR_PREFIX_LEN {
                    buf[ip_offset + IPV4_HDR_CHECKSUM_OFFSET..ip_offset + IPV4_HDR_CHECKSUM_OFFSET + 2]
                        .copy_from_slice(&[0, 0]);
                }
            }
            UdpOverwriteChecksum::ComputeInSoftware => {
                let (src_ip, dst_ip) = ipv4_endpoints.expect("resolved for software checksums");
                buf[udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET
                    ..udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET + 2]
                    .copy_from_slice(&[0, 0]);
                let udp_checksum =
                    compute_udp_checksum_v4(src_ip, dst_ip, &buf[ip_body_start..payload_end]);
                buf[udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET
                    ..udp_hdr.header_range.start + UDP_CHECKSUM_OFFSET + 2]
                    .copy_from_slice(&udp_checksum);

                if ip_body_start - ip_offset >= HDR_PREFIX_LEN {
                    buf[ip_offset + IPV4_HDR_CHECKSUM_OFFSET..ip_offset + IPV4_HDR_CHECKSUM_OFFSET + 2]
                        .copy_from_slice(&[0, 0]);
                    let ip_checksum =
                        compute_ipv4_header_checksum(&buf[ip_offset..ip_offset + HDR_PREFIX_LEN]);
                    buf[ip_offset + IPV4_HDR_CHECKSUM_OFFSET..ip_offset + IPV4_HDR_CHECKSUM_OFFSET + 2]
                        .copy_from_slice(&ip_checksum);
                }
            }
        }

        self.view.update_udp_header_view(u16::try_from(udp_len).unwrap_or(u16::MAX));
        Ok(())
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

impl ReceivedUdpDatagramView {
    /// Returns a [`UdpOverwriter`] with [`UdpOverwriteChecksum::NicOffload`].
    pub fn udp_overwriter(&mut self) -> UdpOverwriter<'_> {
        UdpOverwriter::new(self)
    }

    /// Returns a [`UdpOverwriter`] with the given checksum mode.
    pub fn udp_overwriter_with_checksum(&mut self, checksum: UdpOverwriteChecksum) -> UdpOverwriter<'_> {
        UdpOverwriter::with_checksum(self, checksum)
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
    use packet_formats::udp::UdpPacketBuilder;

    use super::*;
    use crate::view::IpFragmentMetadata;
    use crate::view::{IpFragmentInfo, ReassemblyOutcome};

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

    fn assert_length_fields_and_zero_checksums(
        frame: &[u8],
        expected_ip_total: u16,
        expected_udp_len: u16,
        udp_header_start: usize,
    ) {
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let ip_total = u16::from_be_bytes([
            frame[ip_offset + IPV4_TOTAL_LEN_OFFSET],
            frame[ip_offset + IPV4_TOTAL_LEN_OFFSET + 1],
        ]);
        assert_eq!(ip_total, expected_ip_total);
        assert_eq!(
            [
                frame[ip_offset + IPV4_HDR_CHECKSUM_OFFSET],
                frame[ip_offset + IPV4_HDR_CHECKSUM_OFFSET + 1],
            ],
            [0, 0],
            "IPv4 header checksum left zero for NIC offload"
        );
        let udp_len = u16::from_be_bytes([
            frame[udp_header_start + UDP_LENGTH_OFFSET],
            frame[udp_header_start + UDP_LENGTH_OFFSET + 1],
        ]);
        assert_eq!(udp_len, expected_udp_len);
        assert_eq!(
            [
                frame[udp_header_start + UDP_CHECKSUM_OFFSET],
                frame[udp_header_start + UDP_CHECKSUM_OFFSET + 1],
            ],
            [0, 0],
            "UDP checksum left zero for NIC offload"
        );
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

            fn receive_tcp_segment(
                &mut self,
                _device: &FakeDeviceId,
                _view: crate::view::ReceivedTcpSegmentView,
            ) -> Result<(), IpsReceiveError> {
                Ok(())
            }

            fn receive_icmp_message(
                &mut self,
                _device: &FakeDeviceId,
                _view: crate::view::ReceivedIcmpMessageView,
            ) -> Result<(), IpsReceiveError> {
                Ok(())
            }

            fn receive_igmp_message(
                &mut self,
                _device: &FakeDeviceId,
                _view: crate::view::ReceivedIgmpMessageView,
            ) -> Result<(), IpsReceiveError> {
                Ok(())
            }

            fn receive_pim_message(
                &mut self,
                _device: &FakeDeviceId,
                _view: crate::view::ReceivedPimMessageView,
            ) -> Result<(), IpsReceiveError> {
                Ok(())
            }

            fn receive_ipsec_message(
                &mut self,
                _device: &FakeDeviceId,
                _view: crate::view::ReceivedIpsecMessageView,
            ) -> Result<(), IpsReceiveError> {
                Ok(())
            }        }

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
        use packet::ParsablePacket;
        use packet_formats::ipv4::{Ipv4Header, Ipv4PacketRaw};

        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let ip_total = u16::from_be_bytes([
            frame[ip_offset + IPV4_TOTAL_LEN_OFFSET],
            frame[ip_offset + IPV4_TOTAL_LEN_OFFSET + 1],
        ]);
        let mut bytes = &frame[ip_offset..];
        let raw = Ipv4PacketRaw::parse(&mut bytes, ()).expect("IPv4 raw packet");
        (ip_total, raw.mf_flag(), raw.fragment_offset().into_raw())
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
        let udp_hdr_start = view.udp_header().unwrap().header_range.start;
        assert_length_fields_and_zero_checksums(frame, EXPECTED_IP_TOTAL, EXPECTED_UDP_LEN, udp_hdr_start);
        assert_eq!(
            frame.len(),
            ETHERNET_HDR_LEN_NO_TAG + usize::from(EXPECTED_IP_TOTAL),
            "consolidated frame must be truncated to wire length"
        );
    }

    #[test]
    fn overwrite_shrinks_payload_and_zeros_checksums() {
        let mut view = build_unfragmented_udp(&[0xAA; 64]);
        view.udp_overwriter()
            .overwrite_payload(&[0xBB; 32])
            .expect("overwrite");

        assert_eq!(view.payload_slices().iter().map(|s| s.len()).sum::<usize>(), 32);
        assert_eq!(view.udp_header().unwrap().length, 40);
        let frame = view.eth_frames().next().unwrap();
        let udp_hdr_start = view.udp_header().unwrap().header_range.start;
        assert_length_fields_and_zero_checksums(frame, 60, 40, udp_hdr_start);
        assert_eq!(view.payload_slices().iter().next().unwrap(), &[0xBB; 32]);

        let (ip_total, mf, frag_off) = parsed_ipv4_fields(frame);
        assert_eq!(ip_total, 60);
        assert!(!mf);
        assert_eq!(frag_off, 0);

        let frag = &view.ip_fragments()[0];
        assert_eq!(frag.ip_packet_range.end, frame.len(), "frame buffer must match wire length");
    }

    #[test]
    fn overwrite_shrinks_payload_and_computes_checksums_in_software() {
        use packet::ParsablePacket;
        use packet_formats::ipv4::Ipv4Packet;

        let mut view = build_unfragmented_udp(&[0xAA; 64]);
        view.udp_overwriter_with_checksum(UdpOverwriteChecksum::ComputeInSoftware)
            .overwrite_payload(&[0xBB; 32])
            .expect("overwrite");

        let frame = view.eth_frames().next().unwrap();
        let udp_hdr_start = view.udp_header().unwrap().header_range.start;
        assert_ne!(
            [
                frame[udp_hdr_start + UDP_CHECKSUM_OFFSET],
                frame[udp_hdr_start + UDP_CHECKSUM_OFFSET + 1],
            ],
            [0, 0],
            "UDP checksum must be computed in software mode"
        );

        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let mut ip_bytes = &frame[ip_offset..];
        Ipv4Packet::parse(&mut ip_bytes, ()).expect("IPv4 header checksum valid in software mode");
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

    fn view_with_reassembly_outcome(outcome: ReassemblyOutcome) -> ReceivedUdpDatagramView {
        let payload = &[0xAA; 8];
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
                reassembly_outcome: outcome,
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

    #[test]
    fn overwrite_rejects_aborted_reassembly() {
        let mut view = view_with_reassembly_outcome(ReassemblyOutcome::AbortedRfc5722Overlap);
        let err = view
            .udp_overwriter()
            .overwrite_payload(&[0xBB; 8])
            .expect_err("aborted assembly must not be writable");
        assert_eq!(err, UdpOverwriteError::ReassemblyAborted);
    }

    #[test]
    fn overwrite_rejects_incomplete_reassembly() {
        let mut view = view_with_reassembly_outcome(ReassemblyOutcome::Incomplete);
        let err = view
            .udp_overwriter()
            .overwrite_payload(&[0xBB; 8])
            .expect_err("incomplete assembly must not be writable");
        assert_eq!(err, UdpOverwriteError::ReassemblyIncomplete);
    }

    #[test]
    fn overwrite_in_place_length_mismatch_errors() {
        let mut view = build_unfragmented_udp(&[0xAA; 8]);
        let err = view
            .udp_overwriter()
            .overwrite_payload_in_place(&[0xBB; 4])
            .expect_err("length mismatch");
        assert_eq!(
            err,
            UdpOverwriteError::PayloadLengthMismatch { expected: 8, got: 4 }
        );
    }
}
