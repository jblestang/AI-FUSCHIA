//! CPU batch authorization using chunked evaluation (SIMD-friendly layout).

use crate::{AuthorizedBitMask, MaskedRangeRule};

/// CPU backend for batch bitmask authorization.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuBatchAuthorize;

impl CpuBatchAuthorize {
    /// Evaluates exact bitmask rules for each value (AND across rules).
    pub fn authorize_exact(&self, values: &[u32], rules: &[AuthorizedBitMask]) -> Vec<bool> {
        if rules.is_empty() {
            return vec![true; values.len()];
        }

        values
            .iter()
            .map(|&value| rules.iter().all(|rule| rule.matches(value)))
            .collect()
    }

    /// Evaluates masked range rules for each value (AND across rules).
    pub fn authorize_range(&self, values: &[u32], rules: &[MaskedRangeRule]) -> Vec<bool> {
        if rules.is_empty() {
            return vec![true; values.len()];
        }

        values
            .iter()
            .map(|&value| rules.iter().all(|rule| rule.matches(value)))
            .collect()
    }
}
