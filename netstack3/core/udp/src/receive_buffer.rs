// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Zero-copy UDP receive payload storage.

use alloc::sync::Arc;
use core::fmt;

use packet::Buf;

/// Payload bytes delivered to a UDP socket.
///
/// Backed by [`Arc`] so multicast / multi-recipient delivery can fan out with
/// refcount-only sharing instead of copying the datagram body.
#[derive(Clone, PartialEq, Eq)]
pub struct UdpReceiveBuffer {
    bytes: Arc<[u8]>,
}

impl fmt::Debug for UdpReceiveBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpReceiveBuffer").field("len", &self.bytes.len()).finish_non_exhaustive()
    }
}

impl UdpReceiveBuffer {
    /// Wraps already-shared payload bytes.
    pub fn from_arc(bytes: Arc<[u8]>) -> Self {
        Self { bytes }
    }

    /// Placeholder payload for `bench-receive` (no bytes copied or allocated per packet).
    #[cfg(feature = "bench-receive")]
    #[allow(static_mut_refs)]
    pub fn bench_receive_placeholder() -> Self {
        static mut PLACEHOLDER: Option<Arc<[u8]>> = None;
        unsafe {
            if PLACEHOLDER.is_none() {
                PLACEHOLDER = Some(Arc::from([]));
            }
            Self::from_arc(Arc::clone(PLACEHOLDER.as_ref().unwrap()))
        }
    }

    /// Moves an owned vec into shared storage without copying payload bytes.
    pub fn from_vec(vec: alloc::vec::Vec<u8>) -> Self {
        Self { bytes: vec.into() }
    }

    /// Takes the UDP payload out of a [`Buf`] after parsing (zero-copy move).
    pub fn from_buf(buffer: Buf<alloc::vec::Vec<u8>>) -> Self {
        Self::from_vec(buffer.into_inner())
    }

    /// Copies `body` once into shared storage.
    ///
    /// Used when the underlying RX buffer is reused (e.g. benchmark hot loop).
    pub fn from_slice(body: &[u8]) -> Self {
        Self { bytes: Arc::from(body) }
    }

    /// Returns the payload as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a refcount bump suitable for fan-out delivery.
    pub fn share(&self) -> Self {
        Self { bytes: Arc::clone(&self.bytes) }
    }

    /// Consumes the buffer and returns the underlying shared storage.
    pub fn into_arc(self) -> Arc<[u8]> {
        self.bytes
    }

    /// Builds a payload from a post-IP transport buffer (one move, no byte copy).
    pub fn from_transport_buffer(buffer: Buf<alloc::vec::Vec<u8>>) -> Self {
        Self::from_buf(buffer)
    }

    /// Takes the UDP payload out of an owned transport buffer after parsing.
    ///
    /// Restores the full datagram with [`GrowBuffer::undo_parse`], strips the UDP
    /// header, and moves the payload bytes into shared storage without copying.
    pub fn from_parsed_transport_buffer(
        buffer: &mut Buf<alloc::vec::Vec<u8>>,
        parse_meta: packet::ParseMetadata,
    ) -> Self {
        use packet::{GrowBuffer as _, ShrinkBuffer as _};
        let header_len = parse_meta.header_len();
        buffer.undo_parse(parse_meta);
        buffer.shrink_front(header_len);
        Self::from_transport_buffer(core::mem::replace(buffer, Buf::new(alloc::vec![], ..0)))
    }
}

impl From<alloc::vec::Vec<u8>> for UdpReceiveBuffer {
    fn from(vec: alloc::vec::Vec<u8>) -> Self {
        Self::from_vec(vec)
    }
}

impl From<&[u8]> for UdpReceiveBuffer {
    fn from(slice: &[u8]) -> Self {
        Self::from_slice(slice)
    }
}

impl<const N: usize> From<[u8; N]> for UdpReceiveBuffer {
    fn from(arr: [u8; N]) -> Self {
        Self::from_vec(arr.to_vec())
    }
}
