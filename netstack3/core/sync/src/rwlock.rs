// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Read-write lock implementations for Netstack3.

use net_types::ip::{GenericOverIp, Ip};

#[cfg(not(feature = "single-threaded"))]
pub use std_impl::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(feature = "single-threaded")]
pub use single_threaded_impl::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(not(feature = "single-threaded"))]
mod std_impl {
    use super::*;

    #[cfg(not(loom))]
    pub(crate) use std::sync;
    #[cfg(loom)]
    pub(crate) use loom::sync;

    /// A [`sync::RwLock`] assuming lock poisoning will never occur.
    #[derive(Debug, Default)]
    pub struct RwLock<T>(sync::RwLock<T>);

    /// Lock guard for read access to a [`RwLock`].
    pub type RwLockReadGuard<'a, T> =
        crate::lock_guard::LockGuard<'a, RwLock<T>, sync::RwLockReadGuard<'a, T>>;

    /// Lock guard for write access to a [`RwLock`].
    pub type RwLockWriteGuard<'a, T> =
        crate::lock_guard::LockGuard<'a, RwLock<T>, sync::RwLockWriteGuard<'a, T>>;

    impl<T> RwLock<T> {
        /// Creates a new instance of an `RwLock<T>` which is unlocked.
        pub fn new(t: T) -> RwLock<T> {
            RwLock(sync::RwLock::new(t))
        }

        /// Locks this rwlock with shared read access, blocking the current thread
        /// until it can be acquired.
        ///
        /// See [`sync::RwLock::read`] for more details.
        ///
        /// # Panics
        ///
        /// This method may panic if the calling thread already holds the read or
        /// write lock.
        #[inline]
        #[cfg_attr(feature = "recursive-lock-panic", track_caller)]
        pub fn read(&self) -> RwLockReadGuard<'_, T> {
            crate::lock_guard::LockGuard::new(self, |Self(rw)| {
                rw.read().expect("unexpectedly poisoned")
            })
        }

        /// Locks this rwlock with exclusive write access, blocking the current
        /// thread until it can be acquired.
        ///
        /// See [`sync::RwLock::write`] for more details.
        ///
        /// # Panics
        ///
        /// This method may panic if the calling thread already holds the read or
        /// write lock.
        #[inline]
        #[cfg_attr(feature = "recursive-lock-panic", track_caller)]
        pub fn write(&self) -> RwLockWriteGuard<'_, T> {
            crate::lock_guard::LockGuard::new(self, |Self(rw)| {
                rw.write().expect("unexpectedly poisoned")
            })
        }

        /// Consumes this rwlock, returning the underlying data.
        #[inline]
        pub fn into_inner(self) -> T {
            let Self(rwlock) = self;
            rwlock.into_inner().expect("unexpectedly poisoned")
        }

        /// Returns a mutable reference to the underlying data.
        ///
        /// Since this call borrows the [`RwLock`] mutably, no actual locking needs
        /// to take place. See [`sync::RwLock::get_mut`] for more details.
        #[inline]
        // TODO(https://github.com/tokio-rs/loom/pull/322): remove the disable for
        // loom once loom's lock type supports the method.
        #[cfg(not(loom))]
        pub fn get_mut(&mut self) -> &mut T {
            self.0.get_mut().expect("unexpectedly poisoned")
        }
    }

    impl<T: 'static> lock_order::lock::ReadWriteLock<T> for RwLock<T> {
        type ReadGuard<'l> = RwLockReadGuard<'l, T>;

        type WriteGuard<'l> = RwLockWriteGuard<'l, T>;

        fn read_lock(&self) -> Self::ReadGuard<'_> {
            self.read()
        }

        fn write_lock(&self) -> Self::WriteGuard<'_> {
            self.write()
        }
    }

    impl<T, I: Ip> GenericOverIp<I> for RwLock<T>
    where
        T: GenericOverIp<I>,
    {
        type Type = RwLock<T::Type>;
    }
}

#[cfg(feature = "single-threaded")]
mod single_threaded_impl {
    use core::cell::UnsafeCell;
    use core::ops::{Deref, DerefMut};

    use super::*;

    /// A single-threaded read-write lock with no synchronization overhead.
    ///
    /// This type must only be used when all access happens on a single thread
    /// with no concurrent access. Violating this invariant is undefined behavior.
    #[derive(Debug)]
    pub struct RwLock<T>(UnsafeCell<T>);

    // SAFETY: `RwLock` provides no cross-thread synchronization. These impls match
    // `std::sync::RwLock` so that downstream types (e.g. `WeakRc` socket ids) remain
    // `Send + Sync`. Callers must enable the `single-threaded` feature only when
    // all access to the protected data is confined to a single thread.
    unsafe impl<T: Send> Send for RwLock<T> {}
    unsafe impl<T: Send> Sync for RwLock<T> {}

    impl<T: Default> Default for RwLock<T> {
        fn default() -> Self {
            Self::new(T::default())
        }
    }

    /// Borrowed read guard for a single-threaded [`RwLock`].
    #[derive(Debug)]
    pub struct NoOpReadGuard<'a, T>(&'a T);

    impl<T> Deref for NoOpReadGuard<'_, T> {
        type Target = T;

        fn deref(&self) -> &T {
            self.0
        }
    }

    /// Borrowed write guard for a single-threaded [`RwLock`].
    #[derive(Debug)]
    pub struct NoOpWriteGuard<'a, T>(&'a mut T);

    impl<T> Deref for NoOpWriteGuard<'_, T> {
        type Target = T;

        fn deref(&self) -> &T {
            self.0
        }
    }

    impl<T> DerefMut for NoOpWriteGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            self.0
        }
    }

    /// Lock guard for read access to a [`RwLock`].
    pub type RwLockReadGuard<'a, T> =
        crate::lock_guard::LockGuard<'a, RwLock<T>, NoOpReadGuard<'a, T>>;

    /// Lock guard for write access to a [`RwLock`].
    pub type RwLockWriteGuard<'a, T> =
        crate::lock_guard::LockGuard<'a, RwLock<T>, NoOpWriteGuard<'a, T>>;

    impl<T> RwLock<T> {
        /// Creates a new instance of an `RwLock<T>` which is unlocked.
        pub fn new(t: T) -> RwLock<T> {
            RwLock(UnsafeCell::new(t))
        }

        /// Acquires shared read access to the protected data.
        ///
        /// # Safety
        ///
        /// The caller must ensure that no write guard exists for this lock and
        /// that access is confined to a single thread.
        #[inline]
        #[cfg_attr(feature = "recursive-lock-panic", track_caller)]
        pub fn read(&self) -> RwLockReadGuard<'_, T> {
            crate::lock_guard::LockGuard::new(self, |lock| {
                // SAFETY: Single-threaded access is required by the `single-threaded`
                // feature. Lock ordering instrumentation may additionally panic on
                // conflicting lock acquisition when `recursive-lock-panic` is enabled.
                let data = unsafe { &*lock.0.get() };
                NoOpReadGuard(data)
            })
        }

        /// Acquires exclusive write access to the protected data.
        ///
        /// # Safety
        ///
        /// The caller must ensure that no other guard exists for this lock and
        /// that access is confined to a single thread.
        #[inline]
        #[cfg_attr(feature = "recursive-lock-panic", track_caller)]
        pub fn write(&self) -> RwLockWriteGuard<'_, T> {
            crate::lock_guard::LockGuard::new(self, |lock| {
                // SAFETY: Single-threaded access is required by the `single-threaded`
                // feature. Lock ordering instrumentation may additionally panic on
                // conflicting lock acquisition when `recursive-lock-panic` is enabled.
                let data = unsafe { &mut *lock.0.get() };
                NoOpWriteGuard(data)
            })
        }

        /// Consumes this rwlock, returning the underlying data.
        #[inline]
        pub fn into_inner(self) -> T {
            self.0.into_inner()
        }

        /// Returns a mutable reference to the underlying data.
        #[inline]
        pub fn get_mut(&mut self) -> &mut T {
            self.0.get_mut()
        }
    }

    impl<T: 'static> lock_order::lock::ReadWriteLock<T> for RwLock<T> {
        type ReadGuard<'l> = RwLockReadGuard<'l, T>;

        type WriteGuard<'l> = RwLockWriteGuard<'l, T>;

        fn read_lock(&self) -> Self::ReadGuard<'_> {
            self.read()
        }

        fn write_lock(&self) -> Self::WriteGuard<'_> {
            self.write()
        }
    }

    impl<T, I: Ip> GenericOverIp<I> for RwLock<T>
    where
        T: GenericOverIp<I>,
    {
        type Type = RwLock<T::Type>;
    }
}
