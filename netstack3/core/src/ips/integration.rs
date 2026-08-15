// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Core integration for the IPS receive path.

use alloc::vec::Vec;

use netstack3_device::DeviceId;
use netstack3_device::IpsRxFrameHandler;
use netstack3_ips::{IpsReceiveBindingsContext, process_ethernet_frame};
use packet::Buf;

use crate::{BindingsContext, BindingsTypes, CoreCtx, StackState};

impl<BC: BindingsContext + IpsReceiveBindingsContext<DeviceId<BC>>, L> IpsRxFrameHandler<BC>
    for CoreCtx<'_, BC, L>
{
    type DeviceId = DeviceId<BC>;

    fn ips_ingress_enabled(&self, _device_id: &Self::DeviceId) -> bool {
        self.unlocked_access::<crate::lock_ordering::UnlockedState>().ips.enabled
    }

    fn try_ips_ingress(
        &mut self,
        bindings_ctx: &mut BC,
        device_id: &Self::DeviceId,
        frame: Buf<Vec<u8>>,
    ) -> Result<(), Buf<Vec<u8>>> {
        process_ethernet_frame(
            &self.unlocked_access::<crate::lock_ordering::UnlockedState>().ips,
            bindings_ctx,
            device_id,
            frame,
        )
    }
}

impl<BT: BindingsTypes> StackState<BT> {
    /// Enables IPS ingress on all devices.
    pub fn enable_ips_ingress(&mut self) {
        self.ips.enabled = true;
    }
}
