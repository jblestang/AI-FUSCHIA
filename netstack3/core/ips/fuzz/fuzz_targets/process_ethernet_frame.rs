#![no_main]

use libfuzzer_sys::fuzz_target;
use netstack3_base::testutil::FakeDeviceId;
use netstack3_ips::{
    context::{IpsReceiveBindingsContext, IpsReceiveError},
    process_ethernet_frame, IpsState, ReceivedTcpSegmentView, ReceivedUdpDatagramView,
};
use packet::Buf;

struct FuzzHandler;

impl IpsReceiveBindingsContext<FakeDeviceId> for FuzzHandler {
    fn receive_udp_datagram(
        &mut self,
        _device: &FakeDeviceId,
        view: ReceivedUdpDatagramView,
    ) -> Result<(), IpsReceiveError> {
        let _ = view.payload_slices().iter().map(|slice| slice.len()).sum::<usize>();
        let _ = view.ip_fragments().len();
        Ok(())
    }

    fn receive_tcp_segment(
        &mut self,
        _device: &FakeDeviceId,
        view: ReceivedTcpSegmentView,
    ) -> Result<(), IpsReceiveError> {
        let _ = view.payload_len();
        let _ = view.ip_fragments().len();
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let state = IpsState::new();
    let mut handler = FuzzHandler;
    match process_ethernet_frame(
        &state,
        &mut handler,
        &FakeDeviceId,
        Buf::new(data.to_vec(), ..),
    ) {
        Ok(()) => {
            let _ = state.l7_queue_full_drops();
        }
        Err(_returned) => {}
    }
});
