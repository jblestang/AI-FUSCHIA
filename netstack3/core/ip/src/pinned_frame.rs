// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Shared RX frame storage with in-place mutation for IP receive paths.

use alloc::sync::Arc;
use alloc::vec::Vec;

use either::Either;
use packet::{
    Buffer, Buf, ContiguousBuffer, FragmentedBuffer, FragmentedBufferMut, FragmentedBytes,
    FragmentedBytesMut, GrowBuffer, GrowBufferMut, ParseBuffer, ParseBufferMut, ParsablePacket,
    ShrinkBuffer,
};

/// Mutable receive storage backed by a single [`Arc<[u8]>`].
#[derive(Clone, Debug)]
pub struct PinSlice(Arc<[u8]>);

impl AsRef<[u8]> for PinSlice {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for PinSlice {
    fn as_mut(&mut self) -> &mut [u8] {
        Arc::make_mut(&mut self.0)
    }
}

impl PinSlice {
    fn arc(&self) -> Arc<[u8]> {
        self.0.clone()
    }
}

/// IP receive buffer backed by shared frame storage (one pin at ingress).
#[derive(Clone, Debug)]
pub struct PinnedFrameBuffer {
    inner: Buf<PinSlice>,
}

impl PinnedFrameBuffer {
    /// Takes ownership of `vec` into shared storage (no further payload copies).
    pub fn from_vec(vec: Vec<u8>) -> Self {
        let arc: Arc<[u8]> = Arc::from(vec);
        let len = arc.len();
        Self { inner: Buf::new(PinSlice(arc), 0..len) }
    }

    /// Takes ownership of a [`Buf`] into shared storage.
    pub fn from_buf(buf: Buf<Vec<u8>>) -> Self {
        Self::from_vec(buf.into_inner())
    }

    /// Returns shared frame bytes for upper-layer range views.
    pub fn frame_storage(&self) -> Arc<[u8]> {
        let (pin, _) = self.inner.clone().into_parts();
        pin.arc()
    }
}

impl AsRef<[u8]> for PinnedFrameBuffer {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl AsMut<[u8]> for PinnedFrameBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut()
    }
}

impl FragmentedBuffer for PinnedFrameBuffer {
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn with_bytes<'a, R, F>(&'a self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, 'a>) -> R,
    {
        self.inner.with_bytes(f)
    }

    fn to_flattened_vec(&self) -> Vec<u8> {
        self.inner.to_flattened_vec()
    }
}

impl FragmentedBufferMut for PinnedFrameBuffer {
    fn with_bytes_mut<'a, R, F>(&'a mut self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytesMut<'b, 'a>) -> R,
    {
        self.inner.with_bytes_mut(f)
    }
}

impl ShrinkBuffer for PinnedFrameBuffer {
    fn shrink<R: core::ops::RangeBounds<usize>>(&mut self, range: R) {
        self.inner.shrink(range)
    }

    fn shrink_front(&mut self, n: usize) {
        self.inner.shrink_front(n)
    }

    fn shrink_back(&mut self, n: usize) {
        self.inner.shrink_back(n)
    }
}

impl GrowBuffer for PinnedFrameBuffer {
    fn with_parts<'a, O, F>(&'a self, f: F) -> O
    where
        F: for<'b> FnOnce(&'a [u8], FragmentedBytes<'b, 'a>, &'a [u8]) -> O,
    {
        self.inner.with_parts(f)
    }

    fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    fn prefix_len(&self) -> usize {
        self.inner.prefix_len()
    }

    fn suffix_len(&self) -> usize {
        self.inner.suffix_len()
    }

    fn grow_front(&mut self, n: usize) {
        self.inner.grow_front(n)
    }

    fn grow_back(&mut self, n: usize) {
        self.inner.grow_back(n)
    }
}

impl GrowBufferMut for PinnedFrameBuffer {
    fn with_parts_mut<'a, O, F>(&'a mut self, f: F) -> O
    where
        F: for<'b> FnOnce(&'a mut [u8], FragmentedBytesMut<'b, 'a>, &'a mut [u8]) -> O,
    {
        self.inner.with_parts_mut(f)
    }

    fn with_all_contents_mut<'a, O, F>(&'a mut self, f: F) -> O
    where
        F: for<'b> FnOnce(FragmentedBytesMut<'b, 'a>) -> O,
    {
        self.inner.with_all_contents_mut(f)
    }
}

impl ParseBuffer for PinnedFrameBuffer {
    fn parse_with<'a, ParseArgs, P: ParsablePacket<&'a [u8], ParseArgs>>(
        &'a mut self,
        args: ParseArgs,
    ) -> Result<P, P::Error> {
        self.inner.parse_with(args)
    }
}

impl ParseBufferMut for PinnedFrameBuffer {
    fn parse_with_mut<'a, ParseArgs, P: ParsablePacket<&'a mut [u8], ParseArgs>>(
        &'a mut self,
        args: ParseArgs,
    ) -> Result<P, P::Error> {
        self.inner.parse_with_mut(args)
    }
}

impl Buffer for PinnedFrameBuffer {
    fn parse_with_view<'a, ParseArgs, P: ParsablePacket<&'a [u8], ParseArgs>>(
        &'a mut self,
        args: ParseArgs,
    ) -> Result<(P, &'a [u8]), P::Error> {
        self.inner.parse_with_view(args)
    }
}

impl ContiguousBuffer for PinnedFrameBuffer {}

/// Buffers that carry pinned RX frame storage.
pub trait RxFrameStorage {
    /// Returns pinned frame bytes when this buffer owns shared RX storage.
    fn rx_frame_storage(&self) -> Option<Arc<[u8]>>;
}

impl RxFrameStorage for PinnedFrameBuffer {
    fn rx_frame_storage(&self) -> Option<Arc<[u8]>> {
        Some(self.frame_storage())
    }
}

/// Converts an incoming receive buffer into pinned shared frame storage.
pub trait IntoPinnedFrame {
    /// Returns a pinned receive buffer.
    fn into_pinned_frame(self) -> PinnedFrameBuffer;
}

impl IntoPinnedFrame for Buf<Vec<u8>> {
    fn into_pinned_frame(self) -> PinnedFrameBuffer {
        PinnedFrameBuffer::from_buf(self)
    }
}

impl IntoPinnedFrame for Vec<u8> {
    fn into_pinned_frame(self) -> PinnedFrameBuffer {
        PinnedFrameBuffer::from_vec(self)
    }
}

impl IntoPinnedFrame for PinnedFrameBuffer {
    fn into_pinned_frame(self) -> PinnedFrameBuffer {
        self
    }
}

impl<L, R> IntoPinnedFrame for Either<L, R>
where
    R: IntoPinnedFrame,
    L: AsRef<[u8]>,
{
    fn into_pinned_frame(self) -> PinnedFrameBuffer {
        match self {
            Either::Right(r) => r.into_pinned_frame(),
            Either::Left(l) => PinnedFrameBuffer::from_vec(Vec::from(l.as_ref())),
        }
    }
}
