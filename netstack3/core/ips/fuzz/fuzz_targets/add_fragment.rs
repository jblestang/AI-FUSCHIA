#![no_main]

use libfuzzer_sys::fuzz_target;
use net_types::ip::Ipv4Addr;
use netstack3_ips::fragment::{add_fragment, ipv4_key, store_fragment};
use netstack3_ips::state::{AssemblyProgress, IpsFragmentCache};
use packet::Buf;
use packet_formats::ip::IpProto;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let offset = u16::from_be_bytes([data[0], data[1]]) & 0x1FFF;
    let flags = data[2];
    let body_len = usize::from(data[3]).min(256);
    let m_flag = flags & 0x01 != 0;
    let id = u32::from(u16::from_be_bytes([data[2], data[3]]));

    let body = vec![0u8; body_len];
    let frame_len = body.len();
    let stored = store_fragment(
        Buf::new(body, ..),
        0..frame_len,
        id,
        offset,
        m_flag,
        0..frame_len,
    );

    let cache = IpsFragmentCache::<net_types::ip::Ipv4>::new();
    let key = ipv4_key(
        Ipv4Addr::new([192, 0, 2, 1]),
        Ipv4Addr::new([192, 0, 2, 2]),
        id,
        IpProto::Udp,
    );

    match add_fragment(&cache, key, stored) {
        AssemblyProgress::NeedMore | AssemblyProgress::Ready(_) | AssemblyProgress::Aborted(_) => {}
    }
});
