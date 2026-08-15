// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Layer 7 helpers for detecting inconsistent IPv4 Type of Service (TOS) between fragments.

use core::ops::Range;

use packet::ParsablePacket;
use packet_formats::ip::DscpAndEcn;
use packet_formats::ipv4::{Ipv4Header, Ipv4Packet};

use crate::view::ReceivedUdpDatagramView;

/// IPv4 TOS / DSCP+ECN mismatch across fragments of the same datagram.
///
/// RFC 791 requires all fragments of a datagram to carry identical values in
/// header fields that are not allowed to vary per fragment. TOS (the combined
/// DSCP+ECN byte) must match; differing values are a common evasion technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TosMismatch {
    /// IPv4 fragment identification shared by the conflicting fragments.
    pub identification: u32,
    /// Index into [`ReceivedUdpDatagramView::ip_fragments`] for the first TOS seen.
    pub first_fragment_index: usize,
    /// Index into [`ReceivedUdpDatagramView::ip_fragments`] for the conflicting fragment.
    pub conflicting_fragment_index: usize,
    /// TOS observed on the first fragment.
    pub expected: DscpAndEcn,
    /// TOS observed on the conflicting fragment.
    pub observed: DscpAndEcn,
}

/// Reads the IPv4 DSCP+ECN (TOS) byte from a zero-copy Ethernet frame slice.
pub fn ipv4_dscp_and_ecn(frame: &[u8], ip_packet_range: &Range<usize>) -> Option<DscpAndEcn> {
    let mut ip_bytes = frame.get(ip_packet_range.clone())?;
    let packet = Ipv4Packet::parse(&mut ip_bytes, ()).ok()?;
    Some(packet.dscp_and_ecn())
}

/// Returns `Some` when two or more fragments disagree on IPv4 TOS (DSCP+ECN).
///
/// Each fragment's TOS is read directly from the backing frame buffer referenced
/// by [`ReceivedUdpDatagramView::ip_fragments`] — no payload copy is performed.
pub fn detect_tos_mismatch(view: &ReceivedUdpDatagramView) -> Option<TosMismatch> {
    if view.ip_fragments().len() < 2 {
        return None;
    }

    let frames: alloc::vec::Vec<&[u8]> = view.eth_frames().collect();

    let mut baseline: Option<(DscpAndEcn, usize, u32)> = None;

    for (i, frag) in view.ip_fragments().iter().enumerate() {
        let frame = frames.get(frag.eth_frame_index)?;
        let tos = ipv4_dscp_and_ecn(frame, &frag.ip_packet_range)?;

        match baseline {
            None => baseline = Some((tos, i, frag.identification)),
            Some((expected, first_idx, id)) => {
                if tos != expected {
                    return Some(TosMismatch {
                        identification: id,
                        first_fragment_index: first_idx,
                        conflicting_fragment_index: i,
                        expected,
                        observed: tos,
                    });
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;

    use net_types::ethernet::Mac;
    use alloc::vec::Vec;

    use net_types::ip::{IpAddr, Ipv4Addr};
    use netstack3_base::NetworkSerializationContext;
    use packet::{Buf, NestableSerializer as _, Serializer};
    use packet_formats::ethernet::{EtherType, EthernetFrameBuilder};
    use packet_formats::ip::{FragmentOffset, IpProto, Ipv4Proto};
    use packet_formats::ipv4::Ipv4PacketBuilder;
    use packet_formats::udp::UdpPacketBuilder;

    use super::*;
    use crate::view::{IpFragmentInfo, IpFragmentMetadata, ReassemblyOutcome};

    const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
    const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
    const REMOTE_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);
    const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(100).unwrap();
    const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(200).unwrap();
    const FRAGMENT_ID: u16 = 42;
    const FRAGMENT_BODY_LEN: usize = 104;

    fn build_ipv4_fragment(
        fragment_offset: FragmentOffset,
        more_fragments: bool,
        dscp_and_ecn: DscpAndEcn,
        body: Vec<u8>,
    ) -> Buf<Vec<u8>> {
        let mut ip = Ipv4PacketBuilder::new(REMOTE_IP, LOCAL_IP, 64, Ipv4Proto::Proto(IpProto::Udp));
        ip.id(FRAGMENT_ID);
        ip.dscp_and_ecn(dscp_and_ecn);
        ip.mf_flag(more_fragments);
        ip.fragment_offset(fragment_offset);
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let bytes = Buf::new(body, ..)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .expect("serialize fragment")
            .into_inner()
            .into_inner();
        Buf::new(bytes, ..)
    }

    fn fragment_info(
        eth_frame_index: usize,
        frame_len: usize,
        fragment_offset: u16,
        more_fragments: bool,
    ) -> IpFragmentInfo {
        let ip_offset = packet_formats::ethernet::ETHERNET_HDR_LEN_NO_TAG;
        IpFragmentInfo {
            eth_frame_index,
            ip_packet_range: ip_offset..frame_len,
            identification: u32::from(FRAGMENT_ID),
            fragment_offset,
            more_fragments,
            ip_body_range: ip_offset + packet_formats::ipv4::HDR_PREFIX_LEN..frame_len,
        }
    }

    fn view_from_fragments(frames: Vec<Buf<Vec<u8>>>, infos: Vec<IpFragmentInfo>) -> ReceivedUdpDatagramView {
        ReceivedUdpDatagramView::new(
            frames,
            infos,
            IpFragmentMetadata {
                reassembly_outcome: ReassemblyOutcome::Complete,
                ..Default::default()
            },
            None,
            alloc::vec![],
            LOCAL_IP.into(),
            REMOTE_IP.into(),
        )
    }

    #[test]
    fn detect_tos_mismatch_finds_evasion() {
        let udp_start = [
            0x00, 0xc8, 0x00, 0x64, 0x00, 0x08, 0x00, 0x00, // ports + length + checksum
        ];
        let mut body0 = alloc::vec::Vec::with_capacity(FRAGMENT_BODY_LEN);
        body0.extend_from_slice(&udp_start);
        body0.resize(FRAGMENT_BODY_LEN, 0xAA);

        let body1 = alloc::vec![0xBB; FRAGMENT_BODY_LEN];

        let frame0 = build_ipv4_fragment(
            FragmentOffset::ZERO,
            true,
            DscpAndEcn::default(),
            body0,
        );
        let frame1 = build_ipv4_fragment(
            FragmentOffset::new(13).unwrap(),
            false,
            DscpAndEcn::new(0x2e, 0), // EF (DSCP 46) — raw TOS byte 0xB8
            body1,
        );

        let len0 = frame0.as_ref().len();
        let len1 = frame1.as_ref().len();
        let view = view_from_fragments(
            alloc::vec![frame0, frame1],
            alloc::vec![
                fragment_info(0, len0, 0, true),
                fragment_info(1, len1, 13, false),
            ],
        );

        let mismatch = detect_tos_mismatch(&view).expect("expected TOS mismatch");
        assert_eq!(mismatch.identification, u32::from(FRAGMENT_ID));
        assert_eq!(mismatch.first_fragment_index, 0);
        assert_eq!(mismatch.conflicting_fragment_index, 1);
        assert_eq!(mismatch.expected, DscpAndEcn::default());
        assert_eq!(mismatch.observed, DscpAndEcn::new(0x2e, 0));
    }

    #[test]
    fn detect_tos_mismatch_none_when_consistent() {
        let body = alloc::vec![0u8; FRAGMENT_BODY_LEN];
        let frame0 = build_ipv4_fragment(FragmentOffset::ZERO, true, DscpAndEcn::default(), body.clone());
        let frame1 = build_ipv4_fragment(
            FragmentOffset::new(13).unwrap(),
            false,
            DscpAndEcn::default(),
            body,
        );
        let len0 = frame0.as_ref().len();
        let len1 = frame1.as_ref().len();
        let view = view_from_fragments(
            alloc::vec![frame0, frame1],
            alloc::vec![
                fragment_info(0, len0, 0, true),
                fragment_info(1, len1, 13, false),
            ],
        );
        assert!(detect_tos_mismatch(&view).is_none());
    }
}
