// Copyright 2024 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Netstack3 benchmark utilities.

/// Declare a benchmark function.
///
/// When `cfg(test)` is enabled, a module named `name` with a single test called
/// `test_bench` is emitted and it receives [`TestBencher`].
///
/// Note that `$fn` doesn't have to be a named function - it can also be an
/// anonymous closure.
#[macro_export]
macro_rules! bench {
    ($name:ident, $fn:expr) => {
        #[cfg(test)]
        mod $name {
            use super::*;
            #[test]
            fn test_bench() {
                $fn(&mut $crate::testutil::TestBencher);
            }
        }
    };
}

/// A trait to allow faking of the type providing benchmarking.
pub trait Bencher {
    /// Benchmarks `inner` by running it multiple times.
    fn iter<T, F: FnMut() -> T>(&mut self, inner: F);

    /// Abstracts blackboxing.
    ///
    /// `black_box` prevents the compiler from optimizing a function with an
    /// unused return type.
    fn black_box<T>(placeholder: T) -> T;
}

/// A `Bencher` whose `iter` method runs the provided argument a small,
/// fixed number of times.
pub struct TestBencher;

impl Bencher for TestBencher {
    fn iter<T, F: FnMut() -> T>(&mut self, mut inner: F) {
        const NUM_TEST_ITERS: u32 = 3;
        for _ in 0..NUM_TEST_ITERS {
            let _: T = inner();
        }
    }

    #[inline(always)]
    fn black_box<T>(placeholder: T) -> T {
        core::hint::black_box(placeholder)
    }
}
