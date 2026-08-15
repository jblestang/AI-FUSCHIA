// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Layer 7 detection of unnecessary IPv4 fragmentation (forced segmentation).
//!
//! Attackers sometimes split small datagrams into multiple IP fragments even when
//! the full packet would fit the path MTU, to evade middlebox inspection or
//! stress reassembly paths.

use packet_formats::ipv4::HDR_PREFIX_LEN;

use crate::view::{ReceivedUdpDatagramView, ReassemblyOutcome};

/// Standard Ethernet link MTU: maximum IPv4 datagram size (header included).
pub const ETHERNET_IPV4_MTU: usize = 1500;

/// A reassembled datagram was split into multiple fragments despite fitting the path MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForcedIpSegmentation {
    /// IPv4 fragment identification for the datagram.
    pub identification: u32,
    /// Number of IP fragments received for this datagram.
    pub fragment_count: usize,
    /// Reassembled IPv4 datagram size in bytes (standard 20-byte header + IP payload).
    pub ip_datagram_bytes: usize,
    /// Path MTU used for the comparison.
    pub path_mtu: usize,
}

/// Returns the reassembled IPv4 datagram size when reassembly completed successfully.
pub fn reassembled_ipv4_datagram_bytes(view: &ReceivedUdpDatagramView) -> Option<usize> {
    if view.ip_fragment_metadata().reassembly_outcome != ReassemblyOutcome::Complete {
        return None;
    }
    let udp = view.udp_header()?;
    Some(HDR_PREFIX_LEN + usize::from(udp.length))
}

/// Returns `Some` when a successfully reassembled datagram used multiple fragments
/// but the full IPv4 packet would have fit within `path_mtu`.
///
/// Use [`ETHERNET_IPV4_MTU`] for standard Ethernet. Legitimate fragmentation
/// (datagram larger than MTU) returns `None`.
pub fn detect_forced_ip_segmentation(
    view: &ReceivedUdpDatagramView,
    path_mtu: usize,
) -> Option<ForcedIpSegmentation> {
    let fragments = view.ip_fragments();
    if fragments.len() < 2 {
        return None;
    }

    let ip_datagram_bytes = reassembled_ipv4_datagram_bytes(view)?;
    if ip_datagram_bytes > path_mtu {
        return None;
    }

    Some(ForcedIpSegmentation {
        identification: fragments.first()?.identification,
        fragment_count: fragments.len(),
        ip_datagram_bytes,
        path_mtu,
    })
}

#[cfg(test)]
mod tests {
    use net_types::ip::Ipv4Addr;
    use packet_formats::udp::HEADER_BYTES;

    use super::*;
    use crate::view::{IpFragmentInfo, IpFragmentMetadata, UdpHeaderView};

    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
    const REMOTE_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);

    fn view_with_fragments(
        fragment_count: usize,
        udp_length: u16,
        outcome: ReassemblyOutcome,
    ) -> ReceivedUdpDatagramView {
        let fragments: alloc::vec::Vec<IpFragmentInfo> = (0..fragment_count)
            .map(|i| IpFragmentInfo {
                eth_frame_index: i,
                ip_packet_range: 0..128,
                identification: 99,
                fragment_offset: u16::try_from(i * 13).unwrap(),
                more_fragments: i + 1 < fragment_count,
                ip_body_range: 20..128,
            })
            .collect();

        ReceivedUdpDatagramView::new(
            alloc::vec![],
            fragments,
            IpFragmentMetadata {
                reassembly_outcome: outcome,
                ..Default::default()
            },
            Some(UdpHeaderView {
                src_port: 200,
                dst_port: 100,
                length: udp_length,
                eth_frame_index: 0,
                header_range: 20..20 + HEADER_BYTES,
            }),
            alloc::vec![(0, 28..128)],
            LOCAL_IP.into(),
            REMOTE_IP.into(),
        )
    }

    #[test]
    fn detect_forced_segmentation_small_multi_fragment() {
        let view = view_with_fragments(2, 208, ReassemblyOutcome::Complete);
        let hit = detect_forced_ip_segmentation(&view, ETHERNET_IPV4_MTU).expect("forced seg");
        assert_eq!(hit.identification, 99);
        assert_eq!(hit.fragment_count, 2);
        assert_eq!(hit.ip_datagram_bytes, HDR_PREFIX_LEN + 208);
    }

    #[test]
    fn detect_forced_segmentation_none_for_unfragmented() {
        let view = view_with_fragments(1, 64, ReassemblyOutcome::NotApplicable);
        assert!(detect_forced_ip_segmentation(&view, ETHERNET_IPV4_MTU).is_none());
    }

    #[test]
    fn detect_forced_segmentation_none_when_exceeds_mtu() {
        let view = view_with_fragments(4, 4000, ReassemblyOutcome::Complete);
        assert!(detect_forced_ip_segmentation(&view, ETHERNET_IPV4_MTU).is_none());
    }
}
