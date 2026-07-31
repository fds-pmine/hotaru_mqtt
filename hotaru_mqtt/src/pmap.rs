//! Minimal shared map replacing `DashMap` (std-only) for the no_std port.
//!
//! Follows the framework's platform-sync route: `PMutex` is parking_lot
//! under `std` and `spin` under `embedded`, wrapping an
//! `alloc::collections::BTreeMap`. Critical sections are short and never
//! cross an `.await`, which keeps the spin flavour safe on single-core
//! embedded targets. The maps here are per-session / per-dispatcher (u16
//! packet-id space, per-client endpoint keys), so DashMap's sharding bought
//! nothing these workloads notice; if a std broker profile ever shows
//! contention, swap the std arm back to a sharded map behind this same API.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use hotaru_core::marker::PMutex;

pub(crate) struct PMap<K: Ord, V> {
    inner: PMutex<BTreeMap<K, V>>,
}

impl<K: Ord + Copy, V> PMap<K, V> {
    pub fn new() -> Self {
        Self {
            inner: PMutex::new(BTreeMap::new()),
        }
    }

    pub fn insert(&self, key: K, value: V) -> Option<V> {
        self.inner.lock().insert(key, value)
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        self.inner.lock().remove(key)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.lock().contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Clears the map. Entries are dropped *outside* the lock so value drop
    /// glue (ack senders waking waiters, queue senders closing channels)
    /// never runs under the platform mutex — required for the spin flavour.
    pub fn clear(&self) {
        let drained = core::mem::take(&mut *self.inner.lock());
        drop(drained);
    }

    /// Clone-out snapshot for iteration without holding the lock.
    pub fn snapshot(&self) -> Vec<(K, V)>
    where
        V: Clone,
    {
        self.inner.lock().iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// Entry-style: return the value at `key`, inserting `make()` first if
    /// absent. `make` runs under the lock — keep it cheap and non-blocking
    /// (the dispatcher uses it to lazily create a queue and spawn its
    /// worker; `Rt::spawn_detached` schedules without blocking).
    pub fn get_or_insert_with(&self, key: K, make: impl FnOnce() -> V) -> V
    where
        V: Clone,
    {
        self.inner.lock().entry(key).or_insert_with(make).clone()
    }
}
