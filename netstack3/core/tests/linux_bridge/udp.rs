//! UDP receive example for the Linux bridge host.
//!
//! Shows the netstack3 L4 delivery path: pump the stack, then drain
//! `FakeBindingsCtx::take_udp_received`.

use core::num::NonZeroU16;
use std::io;

use net_types::ip::Ipv4;
use netstack3_base::testutil::TestIpExt;
use netstack3_core::device::WeakDeviceId;
use netstack3_core::testutil::{CtxPairExt as _, FakeBindingsCtx, FakeCtxBuilder};
use netstack3_core::udp::UdpSocketId;
use net_types::ZonedAddr;
use packet::Buf;

use super::host::BridgeHost;

/// Default UDP port for the bridge host example.
pub const DEFAULT_UDP_PORT: NonZeroU16 = NonZeroU16::new(4242).unwrap();

type UdpSocket = UdpSocketId<Ipv4, WeakDeviceId<FakeBindingsCtx>, FakeBindingsCtx>;

/// Binds a UDP listener on `port` (all interfaces / wildcard address).
pub fn bind_listener(host: &mut BridgeHost, port: NonZeroU16) -> io::Result<UdpSocket> {
    let mut api = host.ctx_mut().core_api().udp::<Ipv4>();
    let socket = api.create();
    api.listen(&socket, None, Some(port)).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("UDP listen on {port}: {e:?}"))
    })?;
    Ok(socket)
}

/// Drains all pending UDP payloads delivered to `socket` and logs them.
///
/// Call this after [`BridgeHost::pump_once`] or [`BridgeHost::pump_until_idle`].
pub fn drain_received(host: &mut BridgeHost, socket: &UdpSocket, port: NonZeroU16) -> usize {
    let packets = host.ctx_mut().bindings_ctx.take_udp_received(socket);
    let count = packets.len();
    for payload in packets {
        log::info!(
            "UDP received {} byte(s) on port {}: {:?}",
            payload.len(),
            port,
            String::from_utf8_lossy(&payload),
        );
    }
    count
}

/// In-process UDP receive demo (no TAP required). Useful for CI / quick checks.
pub fn self_test() -> io::Result<()> {
    const HELLO: &[u8] = b"Hello from UDP self-test";

    let (mut ctx, _devices) = FakeCtxBuilder::with_addrs(Ipv4::TEST_ADDRS).build();
    ctx.test_api().add_loopback();

    let socket = {
        let mut api = ctx.core_api().udp::<Ipv4>();
        let socket = api.create();
        api.listen(&socket, None, Some(DEFAULT_UDP_PORT)).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("UDP listen: {e:?}"))
        })?;
        socket
    };

    {
        let mut api = ctx.core_api().udp::<Ipv4>();
        api.send_to(
            &socket,
            Some(ZonedAddr::Unzoned(Ipv4::TEST_ADDRS.local_ip)),
            DEFAULT_UDP_PORT.into(),
            Buf::new(HELLO.to_vec(), ..),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("UDP send_to: {e:?}")))?;
    }

    ctx.test_api().handle_queued_rx_packets();

    let packets = ctx.bindings_ctx.take_udp_received(&socket);
    if packets.len() != 1 || packets[0] != HELLO {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("expected one packet {HELLO:?}, got {packets:?}"),
        ));
    }

    log::info!("UDP self-test OK: received {:?}", String::from_utf8_lossy(&packets[0]));
    Ok(())
}
