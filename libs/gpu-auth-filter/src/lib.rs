//! High-throughput batch filtering by comparing values against authorized bitmasks.
//!
//! Each [`AuthorizedBitMask`] rule requires `(value & mask) == (authorized & mask)`.
//! This matches the netstack3 [`MarkMatcher::Marked`] semantics when `start == end ==
//! authorized & mask`.
//!
//! For large batches, use [`BatchAuthorize::Gpu`] (requires the `gpu` feature) to
//! evaluate rules in parallel on a GPU compute shader. Smaller batches or hosts
//! without GPU support should use [`BatchAuthorize::Cpu`].

mod cpu;

#[cfg(feature = "gpu")]
mod gpu;

pub use cpu::CpuBatchAuthorize;

#[cfg(feature = "gpu")]
pub use gpu::GpuBatchAuthorize;

/// A single authorization rule: masked bits of the input must equal the masked
/// authorized value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedBitMask {
    /// Bits that participate in the comparison.
    pub mask: u32,
    /// Required value after masking (only bits set in `mask` are significant).
    pub authorized: u32,
}

impl AuthorizedBitMask {
    /// Creates a rule from mask and authorized value.
    pub const fn new(mask: u32, authorized: u32) -> Self {
        Self { mask, authorized }
    }

    /// Returns whether `value` satisfies this rule.
    #[inline]
    pub fn matches(&self, value: u32) -> bool {
        (value & self.mask) == (self.authorized & self.mask)
    }

    /// Creates a rule equivalent to `MarkMatcher::Marked { mask, start, end: start, invert: false }`.
    pub const fn exact(mask: u32, authorized: u32) -> Self {
        Self::new(mask, authorized)
    }

    /// Creates a rule that accepts any value whose masked bits fall in `[start, end]`.
    ///
    /// Range checks are expanded into multiple exact rules on CPU/GPU batch paths when
    /// the masked span is small; for wide ranges callers should pre-filter on CPU.
    pub fn masked_range(mask: u32, start: u32, end: u32) -> MaskedRangeRule {
        MaskedRangeRule { mask, start, end }
    }
}

/// Inclusive masked range authorization, matching netstack3 mark matchers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskedRangeRule {
    /// Bits that participate in the comparison.
    pub mask: u32,
    /// Inclusive start of the allowed range after masking.
    pub start: u32,
    /// Inclusive end of the allowed range after masking.
    pub end: u32,
}

impl MaskedRangeRule {
    /// Returns whether `value` satisfies this range rule.
    #[inline]
    pub fn matches(&self, value: u32) -> bool {
        let masked = value & self.mask;
        (self.start..=self.end).contains(&masked)
    }
}

/// Backend used to authorize a batch of values.
pub enum BatchAuthorize {
    /// Scalar / chunked CPU evaluation.
    Cpu(CpuBatchAuthorize),
    /// GPU compute evaluation (`gpu` feature).
    #[cfg(feature = "gpu")]
    Gpu(GpuBatchAuthorize),
}

impl BatchAuthorize {
    /// Returns the recommended backend for the host.
    pub fn auto() -> Self {
        #[cfg(feature = "gpu")]
        {
            if let Ok(gpu) = GpuBatchAuthorize::new() {
                return Self::Gpu(gpu);
            }
        }
        Self::Cpu(CpuBatchAuthorize)
    }

    /// Evaluates all rules (AND semantics) for each value in `values`.
    ///
    /// Returns one bool per input value: `true` if authorized, `false` if denied.
    pub fn authorize_exact(
        &self,
        values: &[u32],
        rules: &[AuthorizedBitMask],
    ) -> Vec<bool> {
        match self {
            Self::Cpu(cpu) => cpu.authorize_exact(values, rules),
            #[cfg(feature = "gpu")]
            Self::Gpu(gpu) => gpu.authorize_exact(values, rules),
        }
    }

    /// Evaluates masked range rules (AND semantics) for each value.
    pub fn authorize_range(
        &self,
        values: &[u32],
        rules: &[MaskedRangeRule],
    ) -> Vec<bool> {
        match self {
            Self::Cpu(cpu) => cpu.authorize_range(values, rules),
            #[cfg(feature = "gpu")]
            Self::Gpu(gpu) => gpu.authorize_range(values, rules),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_rule_matches_mark_semantics() {
        let rule = AuthorizedBitMask::exact(0xFF00, 0x1200);
        assert!(rule.matches(0x1234));
        assert!(!rule.matches(0x0034));
    }

    #[test]
    fn range_rule_matches_mark_matcher() {
        let rule = MaskedRangeRule { mask: 0xF, start: 2, end: 5 };
        assert!(rule.matches(0x3));
        assert!(rule.matches(0x15));
        assert!(!rule.matches(0x1));
    }

    #[test]
    fn cpu_batch_authorize_exact() {
        let backend = BatchAuthorize::Cpu(CpuBatchAuthorize);
        let rules = [AuthorizedBitMask::exact(0xFF, 0x10)];
        let values = [0x10u32, 0x11, 0xFF];
        assert_eq!(backend.authorize_exact(&values, &rules), vec![true, false, false]);
    }

    #[test]
    fn cpu_batch_authorize_range() {
        let backend = BatchAuthorize::Cpu(CpuBatchAuthorize);
        let rules = [MaskedRangeRule { mask: 0xF, start: 1, end: 3 }];
        let values = [0x2u32, 0x4, 0x12];
        assert_eq!(backend.authorize_exact(&values, &[]), vec![true, true, true]);
        assert_eq!(backend.authorize_range(&values, &rules), vec![true, false, true]);
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn gpu_matches_cpu_exact() {
        let Ok(gpu) = GpuBatchAuthorize::new() else {
            return;
        };
        let cpu = BatchAuthorize::Cpu(CpuBatchAuthorize);
        let gpu = BatchAuthorize::Gpu(gpu);
        let rules = [
            AuthorizedBitMask::exact(0xFFFF, 0x1000),
            AuthorizedBitMask::exact(0x00FF, 0x0023),
        ];
        let values: Vec<u32> = (0..10_000).map(|i| 0x1000 | (i & 0xFF)).collect();
        assert_eq!(
            cpu.authorize_exact(&values, &rules),
            gpu.authorize_exact(&values, &rules)
        );
    }
}
