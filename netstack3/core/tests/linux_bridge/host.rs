//! Event loop wiring netstack3 FakeBindingsCtx to a Linux TAP behind a bridge.

use std::io;
use std::time::Duration;

use net_types::ip::Ipv4;
use netstack3_base::testutil::TestIpExt;
use netstack3_core::device::{BatchSize, DeviceId, EthernetDeviceId, EthernetLinkDevice};
use netstack3_core::testutil::{CtxPairExt as _, FakeBindingsCtx, FakeCtx, FakeCtxBuilder};
use netstack3_core::TimerId;
use netstack3_core::types::WorkQueueReport;
use packet::Buf;

use super::tap::TapDevice;

pub struct BridgeHost {
    ctx: FakeCtx,
    eth: EthernetDeviceId<FakeBindingsCtx>,
    tap: TapDevice,
}

impl BridgeHost {
    pub fn new(tap_name: &str) -> io::Result<Self> {
        let (ctx, devices) = FakeCtxBuilder::with_addrs(Ipv4::TEST_ADDRS).build();
        let eth = devices.into_iter().next().expect("builder creates one device");
        let tap = TapDevice::attach(tap_name)?;
        Ok(Self { ctx, eth, tap })
    }

    pub fn pump_once(&mut self) -> io::Result<bool> {
        let mut progress = false;

        progress |= self.ctx.test_api().handle_queued_rx_packets();

        let tx_available = std::mem::take(&mut self.ctx.bindings_ctx.state_mut().tx_available);
        for device in tx_available {
            if let DeviceId::Ethernet(eth) = device {
                match self
                    .ctx
                    .core_api()
                    .transmit_queue::<EthernetLinkDevice>()
                    .transmit_queued_frames(
                        &eth,
                        BatchSize::new_saturating(BatchSize::MAX),
                        &mut (),
                    ) {
                    Ok(WorkQueueReport::AllDone | WorkQueueReport::Pending) => progress = true,
                    Err(e) => log::warn!("transmit_queued_frames failed: {e:?}"),
                }
            }
        }

        for (_weak, frame) in self.ctx.bindings_ctx.take_ethernet_frames() {
            self.tap.write_frame(&frame)?;
            progress = true;
        }

        while let Some(frame) = self.tap.read_frame()? {
            self.ctx
                .test_api()
                .receive_ethernet_frame(&self.eth, Buf::new(frame, ..));
            progress = true;
        }

        if self.ctx.trigger_next_timer::<TimerId<FakeBindingsCtx>>().is_some() {
            progress = true;
        }

        Ok(progress)
    }

    pub fn pump_until_idle(&mut self) -> io::Result<()> {
        while self.pump_once()? {}
        Ok(())
    }

    pub fn run(&mut self, idle_timeout: Duration) -> io::Result<()> {
        let mut pollfd = nix::libc::pollfd {
            fd: self.tap.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };

        loop {
            self.pump_until_idle()?;

            let timeout_ms = idle_timeout.as_millis().try_into().unwrap_or(i32::MAX);
            let ret = unsafe { nix::libc::poll(&mut pollfd, 1, timeout_ms) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if ret == 0 {
                continue;
            }
            if pollfd.revents & nix::libc::POLLIN != 0 {
                self.pump_until_idle()?;
            }
        }
    }
}
