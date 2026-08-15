// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Zero-copy transport-layer body extraction from owned IP buffers.

use packet::Buf;

/// Detaches the transport-layer body from an owned IP buffer.
///
/// After this call, `ip_buffer` retains only the IP header bytes (prefix) so
/// [`IcmpErrorSender`](crate::internal::base::IcmpErrorSender) can still
/// `undo_parse` on port-unreachable. The returned buffer owns the transport
/// bytes (UDP/TCP header + payload) without copying.
pub fn detach_transport_body(ip_buffer: &mut Buf<alloc::vec::Vec<u8>>) -> Buf<alloc::vec::Vec<u8>> {
    let (mut storage, body_range) = {
        let placeholder = Buf::new(alloc::vec![], ..0);
        let (storage, body_range) = core::mem::replace(ip_buffer, placeholder).into_parts();
        (storage, body_range)
    };

    let body_start = body_range.start;
    let body_len = body_range.end - body_range.start;

    let mut transport_storage = storage.split_off(body_start);
    transport_storage.truncate(body_len);

    // Keep IP headers in `ip_buffer` with an empty body for ICMP restoration.
    *ip_buffer = Buf::new(storage, body_start..body_start);

    Buf::new(transport_storage, ..body_len)
}

/// Reattaches a transport body previously detached with [`detach_transport_body`].
pub fn reattach_transport_body(
    ip_buffer: &mut Buf<alloc::vec::Vec<u8>>,
    transport: Buf<alloc::vec::Vec<u8>>,
) {
    let (mut prefix, body_start) = {
        let placeholder = Buf::new(alloc::vec![], ..0);
        let (storage, body_range) = core::mem::replace(ip_buffer, placeholder).into_parts();
        (storage, body_range.start)
    };

    let transport_bytes = transport.into_inner();
    let body_end = body_start + transport_bytes.len();
    prefix.extend_from_slice(&transport_bytes);
    *ip_buffer = Buf::new(prefix, body_start..body_end);
}

/// Returns mutable access to the owned IP backing store when present.
#[allow(dead_code)]
pub fn ip_vec_storage_from_either<B: packet::BufferMut + 'static>(
    buffer: &mut packet::Either<B, Buf<alloc::vec::Vec<u8>>>,
) -> Option<&mut Buf<alloc::vec::Vec<u8>>> {
    use core::any::Any;
    match buffer {
        packet::Either::B(b) => Some(b),
        packet::Either::A(a) => (a as &mut dyn Any).downcast_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::{BufferMut as _, ParseBuffer as _};
    use packet_formats::ipv4::Ipv4PacketBuilder;
    use packet_formats::udp::UdpPacketBuilder;
    use netstack3_base::NetworkSerializationContext;

    #[test]
    fn detach_reattach_roundtrip() {
        let udp_payload = b"hello";
        let udp = UdpPacketBuilder::new(
            net_types::ip::Ipv4Addr::new([192, 0, 2, 1]),
            net_types::ip::Ipv4Addr::new([192, 0, 2, 2]),
            100.try_into().unwrap(),
            200.try_into().unwrap(),
        )
        .body(udp_payload)
        .unwrap();
        let ip = Ipv4PacketBuilder::new(
            net_types::ip::Ipv4Addr::new([192, 0, 2, 1]),
            net_types::ip::Ipv4Addr::new([192, 0, 2, 2]),
            64,
            packet_formats::ip::IpProto::Udp.into(),
        )
        .unwrap();
        let frame = ip.body(udp).unwrap().serialize_vec_outer(&mut NetworkSerializationContext::default()).unwrap().into_inner();

        let mut ip_buffer = Buf::new(frame, ..);
        let _packet = ip_buffer.parse_mut::<_, packet_formats::ipv4::Ipv4Packet<_>>().unwrap();

        let original = ip_buffer.as_ref().to_vec();
        let transport = detach_transport_body(&mut ip_buffer);
        reattach_transport_body(&mut ip_buffer, transport);

        assert_eq!(ip_buffer.as_ref(), original.as_slice());
    }
}
