// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! RFC 5722 fragment assembly with zero-copy frame retention.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::ops::Range;

use net_types::ip::{Ip, Ipv4, Ipv6};
use netstack3_hashmap::hash_map::{Entry, HashMap};
use packet::Buf;
use packet_formats::ip::IpProto;

use crate::state::{
    AssemblyKey, AssemblyProgress, BlockRange, DatagramAssembly, FRAGMENT_BLOCK_SIZE,
    MAX_FRAGMENT_BLOCKS, StoredFragment,
};
use crate::view::FragmentEvent;

/// Result of attempting to place a fragment block range into the assembly.
enum FindGapResult {
    Found { gap: BlockRange },
    Overlap,
    Duplicate,
    OutOfBounds,
}

fn find_gap(
    missing_blocks: &BTreeSet<BlockRange>,
    fragments: &[StoredFragment],
    range: BlockRange,
) -> FindGapResult {
    let BlockRange { start, end } = range;
    let result = missing_blocks.iter().find_map(|gap| {
        if gap.start <= start && gap.end >= end {
            return Some(FindGapResult::Found { gap: *gap });
        }
        if gap.start > end || gap.end < start {
            return None;
        }
        Some(FindGapResult::Overlap)
    });

    match result {
        Some(result) => result,
        None => {
            let last_offset = fragments
                .iter()
                .map(|f| f.fragment_offset)
                .max()
                .unwrap_or(0);
            if last_offset < start {
                FindGapResult::OutOfBounds
            } else {
                FindGapResult::Duplicate
            }
        }
    }
}

fn fragment_blocks_range(offset: u16, body_len: usize, m_flag: bool) -> Result<BlockRange, ()> {
    if body_len == 0 {
        return Err(());
    }
    let num_blocks = body_len.div_ceil(FRAGMENT_BLOCK_SIZE);
    let num_blocks = u16::try_from(num_blocks).map_err(|_| ())?;
    if num_blocks == 0 {
        return Err(());
    }
    let offset_end = offset.checked_add(num_blocks - 1).ok_or(())?;
    if offset_end > MAX_FRAGMENT_BLOCKS {
        return Err(());
    }
    if !m_flag && body_len % FRAGMENT_BLOCK_SIZE != 0 {
        // Last fragment may be unaligned; allowed.
    } else if m_flag && body_len % FRAGMENT_BLOCK_SIZE != 0 {
        return Err(());
    }
    Ok(BlockRange { start: offset, end: offset_end })
}

/// Adds a fragment to the assembly cache, applying RFC 5722 overlap policy.
pub fn add_fragment<I: Ip>(
    cache: &crate::state::IpsFragmentCache<I>,
    key: AssemblyKey<I>,
    stored: StoredFragment,
) -> AssemblyProgress<I> {
    let mut assemblies = cache.assemblies().borrow_mut();

    let offset = stored.fragment_offset;
    let m_flag = stored.more_fragments;
    let body_len = stored.ip_body_range.len();

    let fragment_blocks = match fragment_blocks_range(offset, body_len, m_flag) {
        Ok(r) => r,
        Err(()) => {
            let assembly = abort_assembly(
                &mut assemblies,
                key,
                stored,
                FragmentEvent::OverlappingFragment {
                    identification: key.identification,
                    fragment_offset: offset,
                    conflicting_fragment_index: 0,
                },
            );
            return AssemblyProgress::Aborted(assembly);
        }
    };

    assemblies.entry(key).or_insert_with(|| {
        let mut missing = BTreeSet::new();
        missing.insert(BlockRange { start: 0, end: u16::MAX });
        DatagramAssembly {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            identification: key.identification,
            fragments: Vec::new(),
            events: Vec::new(),
            missing_blocks: missing,
            aborted: false,
        }
    });
    let assembly = assemblies.get_mut(&key).unwrap();

    if assembly.aborted {
        assembly.fragments.push(stored);
        return AssemblyProgress::Aborted(assemblies.remove(&key).unwrap());
    }

    match find_gap(&assembly.missing_blocks, &assembly.fragments, fragment_blocks) {
        FindGapResult::Overlap | FindGapResult::OutOfBounds => {
            let event = FragmentEvent::OverlappingFragment {
                identification: key.identification,
                fragment_offset: offset,
                conflicting_fragment_index: assembly.fragments.len(),
            };
            assembly.events.push(event);
            assembly.aborted = true;
            assembly.fragments.push(stored);
            assembly.missing_blocks.clear();
            return AssemblyProgress::Aborted(assemblies.remove(&key).unwrap());
        }
        FindGapResult::Duplicate => {
            assembly.events.push(FragmentEvent::DuplicateFragment {
                identification: key.identification,
                fragment_offset: offset,
            });
            return AssemblyProgress::NeedMore;
        }
        FindGapResult::Found { gap } => {
            if !m_flag && gap.end < u16::MAX {
                assembly.aborted = true;
                assembly.fragments.push(stored);
                return AssemblyProgress::Aborted(assemblies.remove(&key).unwrap());
            }

            assert!(assembly.missing_blocks.remove(&gap));

            if gap.start < fragment_blocks.start {
                assembly.missing_blocks.insert(BlockRange {
                    start: gap.start,
                    end: fragment_blocks.start - 1,
                });
            }
            if gap.end > fragment_blocks.end && m_flag {
                assembly.missing_blocks.insert(BlockRange {
                    start: fragment_blocks.end + 1,
                    end: gap.end,
                });
            }

            assembly.fragments.push(stored);

            if assembly.missing_blocks.is_empty() {
                return AssemblyProgress::Ready(assemblies.remove(&key).unwrap());
            } else {
                return AssemblyProgress::NeedMore;
            }
        }
    }
}

fn abort_assembly<I: Ip>(
    assemblies: &mut HashMap<AssemblyKey<I>, DatagramAssembly<I>>,
    key: AssemblyKey<I>,
    stored: StoredFragment,
    event: FragmentEvent,
) -> DatagramAssembly<I> {
    match assemblies.entry(key) {
        Entry::Occupied(mut e) => {
            let assembly = e.get_mut();
            assembly.aborted = true;
            assembly.events.push(event);
            assembly.fragments.push(stored);
            assemblies.remove(&key).unwrap()
        }
        Entry::Vacant(_v) => DatagramAssembly {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            identification: key.identification,
            fragments: alloc::vec![stored],
            events: alloc::vec![event],
            missing_blocks: BTreeSet::new(),
            aborted: true,
        },
    }
}

/// Extracts stored frame from a full Ethernet buffer and IP packet range.
pub fn store_fragment(
    eth_frame: Buf<Vec<u8>>,
    ip_packet_range: Range<usize>,
    identification: u32,
    fragment_offset: u16,
    more_fragments: bool,
    ip_body_range: Range<usize>,
) -> StoredFragment {
    StoredFragment {
        eth_frame,
        ip_packet_range,
        identification,
        fragment_offset,
        more_fragments,
        ip_body_range,
    }
}

/// Returns true if the given protocol is UDP.
pub fn is_udp_proto(proto: IpProto) -> bool {
    proto == IpProto::Udp
}

/// Creates an assembly key for IPv4.
pub fn ipv4_key(
    src: net_types::ip::Ipv4Addr,
    dst: net_types::ip::Ipv4Addr,
    id: u32,
    proto: IpProto,
) -> AssemblyKey<Ipv4> {
    AssemblyKey::new(src, dst, id, proto)
}

/// Creates an assembly key for IPv6.
pub fn ipv6_key(
    src: net_types::ip::Ipv6Addr,
    dst: net_types::ip::Ipv6Addr,
    id: u32,
    proto: IpProto,
) -> AssemblyKey<Ipv6> {
    AssemblyKey::new(src, dst, id, proto)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::state::IpsFragmentCache;
    use net_types::ip::Ipv4Addr;
    use packet::Buf;

    fn stored(offset: u16, body_len: usize, m_flag: bool, id: u32) -> StoredFragment {
        let body = vec![0u8; body_len];
        let frame = Buf::new(body, ..);
        store_fragment(frame, 0..body_len, id, offset, m_flag, 0..body_len)
    }

    #[test]
    fn udp_and_tcp_assemblies_use_distinct_cache_keys() {
        let src = Ipv4Addr::new([1, 0, 0, 1]);
        let dst = Ipv4Addr::new([2, 0, 0, 1]);
        let udp_key = ipv4_key(src, dst, 42, IpProto::Udp);
        let tcp_key = ipv4_key(src, dst, 42, IpProto::Tcp);
        assert_ne!(udp_key, tcp_key);
    }

    #[test]
    fn rfc5722_overlap_aborts() {
        let cache = IpsFragmentCache::<Ipv4>::new();
        let src = Ipv4Addr::new([1, 0, 0, 1]);
        let dst = Ipv4Addr::new([2, 0, 0, 1]);
        let key = ipv4_key(src, dst, 5, IpProto::Udp);

        assert!(matches!(
            add_fragment(&cache, key, stored(12, 104, true, 5)),
            AssemblyProgress::NeedMore
        ));

        assert!(matches!(
            add_fragment(&cache, key, stored(6, 104, true, 5)),
            AssemblyProgress::Aborted(_)
        ));
    }
}
