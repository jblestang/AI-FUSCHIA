// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! View-only transport access within IP datagram buffers.
//!
//! Transport bytes are passed as subslices of the IP buffer (`Buf::new(body, ..)`).
//! Payload views are built from [`ReceiveIpPacketMeta::frame_storage`].
