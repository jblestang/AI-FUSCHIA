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
//! sudo cargo run -p netstack3-ips --features testutils --example passive_capture -- --interface eth1
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
    use netstack3_base::testutil::FakeDeviceId;
    use netstack3_ips::{
        IpsReceiveBindingsContext, IpsReceiveError, IpsState, ReceivedTcpSegmentView,
        ReceivedUdpDatagramView, process_ethernet_frame,
    };
    use packet::Buf;

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
        verbose: bool,
    }

    impl FlowAnalyzer {
        fn log_udp(&mut self, view: &ReceivedUdpDatagramView) {
            let (src, dst) = view.addrs();
            let ports = view.udp_header().map(|h| (h.src_port, h.dst_port));
            let payload_len: usize = view.payload_slices().iter().map(|s| s.len()).sum();
            let outcome = view.ip_fragment_metadata().reassembly_outcome;
            if self.verbose {
                println!(
                    "UDP {src} -> {dst} ports={ports:?} payload={payload_len}B reassembly={outcome:?}"
                );
            }
        }

        fn log_tcp(&mut self, view: &ReceivedTcpSegmentView) {
            let (src, dst) = view.addrs();
            let hdr = view.tcp_header();
            let payload_len: usize = view.payload_slices().iter().map(|s| s.len()).sum();
            let outcome = view.ip_fragment_metadata().reassembly_outcome;
            if self.verbose {
                if let Some(h) = hdr {
                    let src_port = h.src_port;
                    let dst_port = h.dst_port;
                    println!(
                        "TCP {src}:{src_port} -> {dst}:{dst_port} seq={} ack={} syn={} fin={} rst={} payload={payload_len}B reassembly={outcome:?}",
                        h.seq_num,
                        h.ack_num,
                        h.syn_flag,
                        h.fin_flag,
                        h.rst_flag,
                    );
                } else {
                    println!("TCP {src} -> {dst} payload={payload_len}B reassembly={outcome:?}");
                }
            }
        }
    }

    impl IpsReceiveBindingsContext<FakeDeviceId> for FlowAnalyzer {
        fn receive_udp_datagram(
            &mut self,
            _device_id: &FakeDeviceId,
            view: ReceivedUdpDatagramView,
        ) -> Result<(), IpsReceiveError> {
            self.stats.udp_delivered += 1;
            self.log_udp(&view);
            Ok(())
        }

        fn receive_tcp_segment(
            &mut self,
            _device_id: &FakeDeviceId,
            view: ReceivedTcpSegmentView,
        ) -> Result<(), IpsReceiveError> {
            self.stats.tcp_delivered += 1;
            self.log_tcp(&view);
            Ok(())
        }
    }

    fn usage() -> ! {
        eprintln!(
            "Usage: passive_capture --interface IFACE [--promisc] [--verbose]\n\
             \n\
             Passive read-only IDS tap using AF_PACKET (no transmit, no inline modification).\n\
             Point IFACE at a SPAN/mirror port or dedicated sniff NIC — not the live gateway path."
        );
        std::process::exit(2);
    }

    fn parse_args() -> (String, bool, bool) {
        let mut args = std::env::args().skip(1);
        let mut interface = None;
        let mut promisc = false;
        let mut verbose = false;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--interface" | "-i" => {
                    interface = args.next();
                }
                "--promisc" => promisc = true,
                "--verbose" | "-v" => verbose = true,
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
        (interface, promisc, verbose)
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
        let (interface, promisc, verbose) = parse_args();

        eprintln!(
            "IPS passive capture on {interface} (read-only AF_PACKET, promisc={promisc}, verbose={verbose})"
        );
        eprintln!("Press Ctrl+C to stop. This process does not transmit on {interface}.");

        unsafe {
            signal(SIGINT, on_signal as usize);
            signal(SIGTERM, on_signal as usize);
        }

        let fd = open_passive_socket(&interface, promisc)?;
        let device_id = FakeDeviceId;
        let state = IpsState::new();
        let mut handler = FlowAnalyzer { stats: CaptureStats::default(), verbose };

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
                Err(_frame) => handler.stats.frames_rejected += 1,
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
