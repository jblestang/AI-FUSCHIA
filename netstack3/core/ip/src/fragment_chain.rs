// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Chained packet storage for zero-copy IP fragment reassembly and layered views.

use alloc::sync::Arc;
use core::ops::Range;

use internet_checksum::Checksum;
use packet::{FragmentedBuffer, FragmentedBytes};
use packet_formats::ipv4::HDR_PREFIX_LEN;

/// A byte range within shared storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketSegment {
    storage: Arc<[u8]>,
    range: Range<usize>,
}

impl PacketSegment {
    /// Captures `bytes` in shared storage (one allocation; no further copies of these bytes).
    pub fn capture(bytes: &[u8]) -> Self {
        let storage: Arc<[u8]> = Arc::from(bytes);
        let len = storage.len();
        Self { storage, range: 0..len }
    }

    /// Views `subslice` within already-shared `storage`.
    ///
    /// Returns `None` when `subslice` does not lie wholly inside `storage` (e.g. after
    /// copy-on-write split between the arc and the live packet buffer).
    pub fn view_of_subslice(storage: Arc<[u8]>, subslice: &[u8]) -> Option<Self> {
        let base = storage.as_ptr() as usize;
        let limit = base.saturating_add(storage.len());
        let start = subslice.as_ptr() as usize;
        let end = start.saturating_add(subslice.len());
        (start >= base && end <= limit).then(|| {
            let offset = start - base;
            Self { storage, range: offset..offset + subslice.len() }
        })
    }

    /// Views `subslice` within already-shared `storage`.
    pub fn view_in(storage: Arc<[u8]>, range: Range<usize>) -> Self {
        debug_assert!(
            range.start <= range.end && range.end <= storage.len(),
            "PacketSegment range {range:?} out of bounds for storage len {}",
            storage.len()
        );
        Self { storage, range }
    }

    /// Returns the segment bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.range.clone()]
    }

    /// Shared backing storage and range.
    pub fn parts(&self) -> (&Arc<[u8]>, Range<usize>) {
        (&self.storage, self.range.clone())
    }

    pub fn len(&self) -> usize {
        self.range.end - self.range.start
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A reassembled IP datagram represented as a header segment followed by chained body segments.
///
/// No body bytes are copied during reassembly; fragments remain in their original RX storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReassembledChain {
    header: PacketSegment,
    bodies: alloc::vec::Vec<PacketSegment>,
}

impl ReassembledChain {
    /// Total reassembled packet length in bytes.
    pub fn total_len(&self) -> usize {
        self.header.len() + self.bodies.iter().map(|b| b.len()).sum::<usize>()
    }

    pub fn header(&self) -> &PacketSegment {
        &self.header
    }

    pub fn bodies(&self) -> &[PacketSegment] {
        &self.bodies
    }

    /// Iterates all segments in on-the-wire order (header, then body fragments).
    pub fn segments_in_order(&self) -> impl Iterator<Item = &PacketSegment> {
        core::iter::once(&self.header).chain(self.bodies.iter())
    }

    /// Builds a contiguous buffer for legacy parse paths that require [`ParseBuffer`].
    pub fn into_contiguous_vec(self) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::with_capacity(self.total_len());
        v.extend_from_slice(self.header.as_slice());
        for body in self.bodies {
            v.extend_from_slice(body.as_slice());
        }
        v
    }

    /// Patches an IPv4 header segment in place (total length, frag fields, checksum).
    pub fn patch_ipv4_header(segment: &mut PacketSegment, total_len: usize) -> Result<(), ()> {
        if segment.len() < HDR_PREFIX_LEN {
            return Err(());
        }
        let storage = Arc::make_mut(&mut segment.storage);
        let range = segment.range.clone();
        let bytes = &mut storage[range.clone()];
        if total_len > usize::from(u16::MAX) {
            return Err(());
        }
        bytes[2..4].copy_from_slice(&u16::try_from(total_len).map_err(|_| ())?.to_be_bytes());
        bytes[6] &= !0x3f; // clear flags + fragment offset high bits
        bytes[7] = 0;
        bytes[10..12].copy_from_slice(&[0, 0]);
        let mut c = Checksum::new();
        c.add_bytes(&bytes[..HDR_PREFIX_LEN]);
        c.add_bytes(&bytes[HDR_PREFIX_LEN..]);
        bytes[10..12].copy_from_slice(&c.checksum());
        Ok(())
    }

    /// Assembles a chain from a patched header and sorted body segments.
    pub fn new(mut header: PacketSegment, bodies: alloc::vec::Vec<PacketSegment>) -> Self {
        let total_len = header.len() + bodies.iter().map(|b| b.len()).sum::<usize>();
        let _ = Self::patch_ipv4_header(&mut header, total_len);
        Self { header, bodies }
    }
}

/// [`FragmentedBuffer`] view over a [`ReassembledChain`] (header + body chain).
#[derive(Clone, Debug)]
pub struct ReassembledChainBuffer {
    chain: ReassembledChain,
}

impl ReassembledChainBuffer {
    pub fn new(chain: ReassembledChain) -> Self {
        Self { chain }
    }

    pub fn into_inner(self) -> ReassembledChain {
        self.chain
    }

    pub fn chain(&self) -> &ReassembledChain {
        &self.chain
    }
}

impl FragmentedBuffer for ReassembledChainBuffer {
    fn len(&self) -> usize {
        self.chain.total_len()
    }

    fn with_bytes<'a, R, F>(&'a self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, 'a>) -> R,
    {
        let header = self.chain.header.as_slice();
        let bodies: alloc::vec::Vec<&[u8]> =
            self.chain.bodies.iter().map(|s| s.as_slice()).collect();
        if bodies.is_empty() {
            let mut slices = [header];
            f(FragmentedBytes::new(&mut slices))
        } else {
            let mut slices: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::with_capacity(1 + bodies.len());
            slices.push(header);
            slices.extend(bodies);
            f(FragmentedBytes::new(&mut slices))
        }
    }
}

/// Layer byte ranges within a logical (reassembled) packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerRanges {
    /// Full IP datagram (header + payload).
    pub ip: Range<usize>,
    /// Transport header + payload (UDP/TCP segment).
    pub transport: Range<usize>,
    /// Transport payload only.
    pub payload: Range<usize>,
}

/// Backing storage for a [`SharedPacketView`].
#[derive(Clone, Debug, PartialEq, Eq)]
enum SharedPacketStorage {
    /// Single pinned RX buffer (typical UDP/TCP segment path).
    Contiguous(Arc<[u8]>),
    /// Reassembled IP fragment chain.
    Segmented(Arc<[PacketSegment]>),
}

/// Shared packet bytes with layer boundaries for userspace inspection.
///
/// Contiguous RX frames store `Arc<[u8]>` directly (no extra wrapper allocation).
/// Reassembled datagrams may also carry an [`Self::ip_fragment_chain`] of original
/// wire fragments for Layer-7 inspection (e.g. per-fragment TOS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedPacketView {
    storage: SharedPacketStorage,
    layers: LayerRanges,
    /// Original IP fragments as received (in increasing fragment-offset order).
    ip_fragment_chain: Option<Arc<[PacketSegment]>>,
}

impl SharedPacketView {
    /// Builds a view over a single contiguous buffer with layer ranges.
    pub fn contiguous(storage: Arc<[u8]>, layers: LayerRanges) -> Self {
        Self::contiguous_with_ip_fragments(storage, layers, None)
    }

    /// Builds a contiguous logical datagram view, optionally retaining wire IP fragments.
    pub fn contiguous_with_ip_fragments(
        storage: Arc<[u8]>,
        layers: LayerRanges,
        ip_fragment_chain: Option<Arc<[PacketSegment]>>,
    ) -> Self {
        Self {
            storage: SharedPacketStorage::Contiguous(storage),
            layers,
            ip_fragment_chain,
        }
    }

    /// Builds a view from a reassembled fragment chain and layer ranges in logical packet space.
    pub fn from_chain(chain: ReassembledChain, layers: LayerRanges) -> Self {
        Self::from_chain_with_ip_fragments(chain, layers, None)
    }

    /// Builds a logical segmented view and attaches the original wire IP fragment chain.
    pub fn from_chain_with_ip_fragments(
        chain: ReassembledChain,
        layers: LayerRanges,
        ip_fragment_chain: Option<Arc<[PacketSegment]>>,
    ) -> Self {
        let segments: alloc::vec::Vec<PacketSegment> = chain.segments_in_order().cloned().collect();
        Self {
            storage: SharedPacketStorage::Segmented(segments.into()),
            layers,
            ip_fragment_chain,
        }
    }

    pub fn layers(&self) -> &LayerRanges {
        &self.layers
    }

    /// Logical reassembly segments (header + body pieces), empty for contiguous storage.
    pub fn segments(&self) -> &[PacketSegment] {
        match &self.storage {
            SharedPacketStorage::Contiguous(_) => &[],
            SharedPacketStorage::Segmented(segments) => segments,
        }
    }

    /// Wire IP fragments as received, sorted by fragment offset.
    ///
    /// `None` for single-frame (non-fragmented) receives. Present when reassembly
    /// captured pinned RX storage for each fragment.
    pub fn ip_fragment_chain(&self) -> Option<&[PacketSegment]> {
        self.ip_fragment_chain.as_deref()
    }

    /// Returns true when the datagram was delivered from a multi-fragment reassembly.
    pub fn is_reassembled_from_fragments(&self) -> bool {
        self.ip_fragment_chain.as_ref().is_some_and(|c| c.len() > 1)
    }

    /// Raw IPv4 TOS byte (header byte 1) from each wire fragment, when present.
    pub fn ipv4_fragment_tos_raw(&self) -> impl Iterator<Item = u8> + '_ {
        self.ip_fragment_chain
            .iter()
            .flat_map(|chain| chain.iter().filter_map(|seg| seg.as_slice().get(1).copied()))
    }

    /// Invokes `f` with the full stored bytes as a fragmented view (zero-copy).
    pub fn with_frame<R, F>(&self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, '_>) -> R,
    {
        self.with_subrange(self.layers.ip.clone(), f)
    }

    /// Invokes `f` with bytes for the transport layer and above.
    pub fn with_transport<R, F>(&self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, '_>) -> R,
    {
        self.with_subrange(self.layers.transport.clone(), f)
    }

    /// Invokes `f` with payload bytes only.
    pub fn with_payload<R, F>(&self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, '_>) -> R,
    {
        self.with_subrange(self.layers.payload.clone(), f)
    }

    /// Returns the payload layer as a contiguous slice when it lies in one segment.
    pub fn payload_as_slice(&self) -> &[u8] {
        self.slice_at(self.layers.payload.clone())
    }

    /// Returns a contiguous subslice of the logical packet when wholly within one segment.
    pub fn slice_at(&self, logical: Range<usize>) -> &[u8] {
        match &self.storage {
            SharedPacketStorage::Contiguous(storage) => {
                let end = logical.end.min(storage.len());
                if logical.start >= end {
                    return &[];
                }
                &storage[logical.start..end]
            }
            SharedPacketStorage::Segmented(segments) => {
                let mut cursor = 0;
                for seg in segments.iter() {
                    let seg_len = seg.len();
                    let seg_start = cursor;
                    let seg_end = cursor + seg_len;
                    cursor = seg_end;
                    if logical.end <= seg_start || logical.start >= seg_end {
                        continue;
                    }
                    if logical.start >= seg_start && logical.end <= seg_end {
                        let local_start = logical.start - seg_start;
                        let local_end = logical.end - seg_start;
                        return &seg.as_slice()[local_start..local_end];
                    }
                    break;
                }
                &[]
            }
        }
    }

    /// Invokes `f` with the full IP datagram bytes.
    pub fn with_ip_datagram<R, F>(&self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, '_>) -> R,
    {
        self.with_subrange(self.layers.ip.clone(), f)
    }

    fn with_subrange<R, F>(&self, logical: Range<usize>, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, '_>) -> R,
    {
        match &self.storage {
            SharedPacketStorage::Contiguous(storage) => {
                let end = logical.end.min(storage.len());
                if logical.start >= end {
                    let mut empty: [&[u8]; 0] = [];
                    return f(FragmentedBytes::new(&mut empty));
                }
                let slice = &storage[logical.start..end];
                let mut slices = [slice];
                f(FragmentedBytes::new(&mut slices))
            }
            SharedPacketStorage::Segmented(segments) => {
                let mut out: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::new();
                let mut cursor = 0;
                for seg in segments.iter() {
                    let seg_len = seg.len();
                    let seg_start = cursor;
                    let seg_end = cursor + seg_len;
                    cursor = seg_end;
                    if seg_end <= logical.start || seg_start >= logical.end {
                        continue;
                    }
                    let local_start = logical.start.saturating_sub(seg_start);
                    let local_end = (logical.end - seg_start).min(seg_len);
                    out.push(&seg.as_slice()[local_start..local_end]);
                }
                f(FragmentedBytes::new(&mut out))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_fragmented_buffer_len() {
        let chain = ReassembledChain {
            header: PacketSegment::capture(&[0u8; 20]),
            bodies: alloc::vec![PacketSegment::capture(&[1, 2, 3]), PacketSegment::capture(&[4, 5])],
        };
        let buf = ReassembledChainBuffer::new(chain);
        assert_eq!(buf.len(), 25);
    }

    #[test]
    fn ip_fragment_chain_exposes_wire_segments() {
        let header = PacketSegment::capture(&[0u8; 20]);
        let body = PacketSegment::capture(&[1, 2, 3]);
        let chain: Arc<[PacketSegment]> = Arc::from([header.clone(), body.clone()]);
        let layers = LayerRanges { ip: 0..23, transport: 20..23, payload: 20..23 };
        let view = SharedPacketView::contiguous_with_ip_fragments(
            Arc::from([0u8; 23]),
            layers,
            Some(chain),
        );
        assert!(view.is_reassembled_from_fragments());
        assert_eq!(view.ip_fragment_chain().unwrap().len(), 2);
        assert!(view.segments().is_empty());
    }
    #[test]
    fn view_of_subslice_rejects_out_of_storage_pointer() {
        let storage = Arc::from([1u8, 2, 3, 4]);
        let foreign = [9u8; 2];
        assert!(PacketSegment::view_of_subslice(storage.clone(), &foreign).is_none());
        assert!(PacketSegment::view_of_subslice(storage, &[]).is_some());
    }
}
