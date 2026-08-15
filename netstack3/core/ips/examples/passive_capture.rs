// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Passive Linux IDS hook: read-only AF_PACKET capture → IPS ingress.
//!
//! This example **never transmits** on the capture interface. It only receives
//! copies of Ethernet frames (typically from a SPAN/mirror port or a dedicated
//! sniff NIC) and feeds them to [`process_ethernet_frame`] for zero-copy L7
//! analysis.
//!
//! ```text
//! # Mirror/SPAN traffic to eth1, leave eth0 as the live path:
//! sudo ./netstack3/core/ips/scripts/ips-passive-monitor.sh eth1
//!
//! # Or run the binary directly:
//! sudo cargo run -p netstack3-ips --example passive_capture -- --interface eth1
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("passive_capture is Linux-only (AF_PACKET).");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux {
    use core::mem;
    use core::sync::atomic::{AtomicBool, Ordering};

    use libc::{
        bind, c_int, c_void, close, if_nametoindex, recvfrom, setsockopt, signal, socket, AF_PACKET,
        ETH_P_ALL, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC, SIGINT, SIGTERM, SOCK_RAW, SOL_PACKET,
    };
    use netstack3_base::{DeviceIdentifier, StrongDeviceIdentifier, WeakDeviceIdentifier};
    use netstack3_ips::{
        IpsReceiveBindingsContext, IpsReceiveError, IpsState, ReceivedTcpSegmentView,
        ReceivedUdpDatagramView, process_ethernet_frame,
    };
    use packet::Buf;

    /// Standalone capture NIC identifier (no `testutils` feature required).
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    struct CaptureDeviceId;

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    struct CaptureWeakDeviceId;

    impl DeviceIdentifier for CaptureDeviceId {
        fn is_loopback(&self) -> bool {
            false
        }
    }

    impl DeviceIdentifier for CaptureWeakDeviceId {
        fn is_loopback(&self) -> bool {
            false
        }
    }

    impl StrongDeviceIdentifier for CaptureDeviceId {
        type Weak = CaptureWeakDeviceId;

        fn downgrade(&self) -> CaptureWeakDeviceId {
            CaptureWeakDeviceId
        }
    }

    impl WeakDeviceIdentifier for CaptureWeakDeviceId {
        type Strong = CaptureDeviceId;

        fn upgrade(&self) -> Option<CaptureDeviceId> {
            Some(CaptureDeviceId)
        }
    }

    impl PartialEq<CaptureWeakDeviceId> for CaptureDeviceId {
        fn eq(&self, _other: &CaptureWeakDeviceId) -> bool {
            true
        }
    }

    impl PartialEq<CaptureDeviceId> for CaptureWeakDeviceId {
        fn eq(&self, _other: &CaptureDeviceId) -> bool {
            true
        }
    }

    #[repr(C)]
    struct SockAddrLl {
        sll_family: u16,
        sll_protocol: u16,
        sll_ifindex: u32,
        sll_hatype: u16,
        sll_pkttype: u8,
        sll_halen: u8,
        sll_addr: [u8; 8],
    }

    #[repr(C)]
    struct PacketMreq {
        mr_ifindex: c_int,
        mr_type: u16,
        mr_alen: u16,
        mr_address: [u8; 8],
    }

    static RUNNING: AtomicBool = AtomicBool::new(true);

    extern "C" fn on_signal(_: c_int) {
        RUNNING.store(false, Ordering::SeqCst);
    }

    #[derive(Default, Debug)]
    struct CaptureStats {
        frames_received: u64,
        frames_accepted: u64,
        frames_rejected: u64,
        udp_delivered: u64,
        tcp_delivered: u64,
        l7_queue_full: u64,
    }

    struct FlowAnalyzer {
        stats: CaptureStats,
    }

    fn log_rejected_frame(bytes: &[u8]) {
        let ethertype = bytes.get(12..14).map(|s| u16::from_be_bytes([s[0], s[1]]));
        let hex_limit = bytes.len().min(64);
        let hex: String = bytes[..hex_limit]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        let truncated = if bytes.len() > hex_limit { " (truncated)" } else { "" };
        match ethertype {
            Some(et) => println!(
                "REJECTED len={} ethertype=0x{et:04x} hex={hex}{truncated}",
                bytes.len()
            ),
            None => println!("REJECTED len={} hex={hex}{truncated}", bytes.len()),
        }
    }

    impl FlowAnalyzer {
        fn note_udp(&mut self, _view: &ReceivedUdpDatagramView) {
            self.stats.udp_delivered += 1;
        }

        fn note_tcp(&mut self, _view: &ReceivedTcpSegmentView) {
            self.stats.tcp_delivered += 1;
        }
    }

    impl IpsReceiveBindingsContext<CaptureDeviceId> for FlowAnalyzer {
        fn receive_udp_datagram(
            &mut self,
            _device_id: &CaptureDeviceId,
            view: ReceivedUdpDatagramView,
        ) -> Result<(), IpsReceiveError> {
            self.note_udp(&view);
            Ok(())
        }

        fn receive_tcp_segment(
            &mut self,
            _device_id: &CaptureDeviceId,
            view: ReceivedTcpSegmentView,
        ) -> Result<(), IpsReceiveError> {
            self.note_tcp(&view);
            Ok(())
        }
    }

    fn usage() -> ! {
        eprintln!(
            "Usage: passive_capture --interface IFACE [--promisc]\n\
             \n\
             Passive read-only IDS tap using AF_PACKET (no transmit, no inline modification).\n\
             Logs only frames rejected by IPS ingress (malformed/non-IP/non-L4/truncated).\n\
             Point IFACE at a SPAN/mirror port or dedicated sniff NIC — not the live gateway path."
        );
        std::process::exit(2);
    }

    fn parse_args() -> (String, bool) {
        let mut args = std::env::args().skip(1);
        let mut interface = None;
        let mut promisc = false;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--interface" | "-i" => {
                    interface = args.next();
                }
                "--promisc" => promisc = true,
                "--help" | "-h" => usage(),
                other => {
                    eprintln!("Unknown argument: {other}");
                    usage();
                }
            }
        }
        let interface = interface.unwrap_or_else(|| {
            eprintln!("Missing --interface IFACE");
            usage();
        });
        (interface, promisc)
    }

    fn open_passive_socket(interface: &str, promisc: bool) -> Result<c_int, String> {
        let ifindex = {
            let c_name = std::ffi::CString::new(interface)
                .map_err(|_| "interface name contains NUL".to_string())?;
            let idx = unsafe { if_nametoindex(c_name.as_ptr().cast()) };
            if idx == 0 {
                return Err(format!("interface {interface} not found"));
            }
            idx
        };

        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ALL as c_int) };
        if fd < 0 {
            return Err("socket(AF_PACKET, SOCK_RAW) failed (need CAP_NET_RAW or root)".into());
        }

        if promisc {
            let mreq = PacketMreq {
                mr_ifindex: ifindex as c_int,
                mr_type: PACKET_MR_PROMISC as u16,
                mr_alen: 0,
                mr_address: [0; 8],
            };
            let rc = unsafe {
                setsockopt(
                    fd,
                    SOL_PACKET,
                    PACKET_ADD_MEMBERSHIP,
                    (&raw const mreq).cast(),
                    mem::size_of::<PacketMreq>() as u32,
                )
            };
            if rc != 0 {
                unsafe { close(fd) };
                return Err(format!("setsockopt(PACKET_MR_PROMISC) failed on {interface}"));
            }
        }

        let addr = SockAddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: (ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            bind(
                fd,
                (&raw const addr).cast(),
                mem::size_of::<SockAddrLl>() as u32,
            )
        };
        if rc != 0 {
            unsafe { close(fd) };
            return Err(format!("bind AF_PACKET to {interface} failed"));
        }

        Ok(fd)
    }

    pub fn run() -> Result<(), String> {
        let (interface, promisc) = parse_args();

        eprintln!(
            "IPS passive capture on {interface} (read-only AF_PACKET, promisc={promisc}; logging rejected frames only)"
        );
        eprintln!("Press Ctrl+C to stop. This process does not transmit on {interface}.");

        unsafe {
            signal(SIGINT, on_signal as usize);
            signal(SIGTERM, on_signal as usize);
        }

        let fd = open_passive_socket(&interface, promisc)?;
        let device_id = CaptureDeviceId;
        let state = IpsState::new();
        let mut handler = FlowAnalyzer { stats: CaptureStats::default() };

        let mut buf = vec![0u8; 65536];
        while RUNNING.load(Ordering::SeqCst) {
            let n = unsafe {
                recvfrom(
                    fd,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
            if n <= 0 {
                if !RUNNING.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            }
            handler.stats.frames_received += 1;
            let frame_bytes = buf[..n as usize].to_vec();
            let frame = Buf::new(frame_bytes, ..);
            match process_ethernet_frame(&state, &mut handler, &device_id, frame) {
                Ok(()) => handler.stats.frames_accepted += 1,
                Err(rejected) => {
                    handler.stats.frames_rejected += 1;
                    log_rejected_frame(rejected.as_ref());
                }
            }
            handler.stats.l7_queue_full = state.l7_queue_full_drops();
        }

        unsafe { close(fd) };

        eprintln!("\n--- capture summary ---");
        eprintln!("{:#?}", handler.stats);
        eprintln!("l7_queue_full_drops (from IpsState): {}", state.l7_queue_full_drops());
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = linux::run() {
        eprintln!("passive_capture error: {e}");
        std::process::exit(1);
    }
}
