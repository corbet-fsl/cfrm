//! Bounded in-memory token buckets keyed by a source or session. State lives in
//! RAM only: nothing is logged, persisted or shared with another process, and
//! this type has no `Debug`, so keys never reach output, errors or metrics.
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use std::{
    collections::HashMap,
    hash::Hash,
    num::NonZeroU32,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Largest accepted key table. The table never grows past its configured bound.
pub const MAXIMUM_KEYS: usize = 1_048_576;

/// One keyed bucket policy: `burst` immediate tokens, one more every
/// `replenish`, at most `keys` tracked keys. Keys beyond the table share one
/// overflow bucket with the same rate as a single key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bucket {
    pub burst: u32,
    pub replenish: Duration,
    pub keys: usize,
}

struct Entry {
    limiter: DefaultDirectRateLimiter,
    last: Instant,
}

pub struct Keyed<K: Hash + Eq + Clone> {
    quota: Quota,
    /// Time after which an unused key has fully replenished and carries no state.
    window: Duration,
    keys: usize,
    table: Mutex<HashMap<K, Entry>>,
    overflow: DefaultDirectRateLimiter,
}

impl<K: Hash + Eq + Clone> Keyed<K> {
    /// Refuses a zero burst, zero replenish interval or an unbounded key table.
    pub fn new(bucket: Bucket) -> Option<Self> {
        if bucket.keys == 0 || bucket.keys > MAXIMUM_KEYS {
            return None;
        }
        let burst = NonZeroU32::new(bucket.burst)?;
        let quota = Quota::with_period(bucket.replenish)?.allow_burst(burst);
        Some(Self {
            quota,
            window: bucket.replenish.saturating_mul(bucket.burst),
            keys: bucket.keys,
            table: Mutex::new(HashMap::new()),
            overflow: RateLimiter::direct(quota),
        })
    }

    fn table(&self) -> std::sync::MutexGuard<'_, HashMap<K, Entry>> {
        self.table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn evict(&self, table: &mut HashMap<K, Entry>, now: Instant) {
        table.retain(|_, entry| now.duration_since(entry.last) < self.window);
        table.shrink_to_fit();
    }

    /// Drop every idle (fully replenished) key.
    pub fn prune(&self) {
        let now = Instant::now();
        self.evict(&mut self.table(), now);
    }

    /// Number of keys currently tracked.
    pub fn tracked(&self) -> usize {
        self.table().len()
    }

    /// Spend one token. A tracked key always uses its own bucket. A new key
    /// joins the table, after dropping idle keys when it is full; if the table
    /// is still full the key shares the single overflow bucket instead of being
    /// refused outright, so table exhaustion throttles but never locks out.
    pub fn admit(&self, key: &K) -> bool {
        let now = Instant::now();
        let mut table = self.table();
        if let Some(entry) = table.get_mut(key) {
            entry.last = now;
            return entry.limiter.check().is_ok();
        }
        if table.len() >= self.keys {
            self.evict(&mut table, now);
        }
        if table.len() >= self.keys {
            return self.overflow.check().is_ok();
        }
        let entry = table.entry(key.clone()).or_insert(Entry {
            limiter: RateLimiter::direct(self.quota),
            last: now,
        });
        entry.limiter.check().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(burst: u32, replenish: Duration, keys: usize) -> Bucket {
        Bucket {
            burst,
            replenish,
            keys,
        }
    }
    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn invalid_policies_are_refused() {
        assert!(Keyed::<u8>::new(bucket(1, HOUR, 0)).is_none());
        assert!(Keyed::<u8>::new(bucket(1, HOUR, MAXIMUM_KEYS + 1)).is_none());
        assert!(Keyed::<u8>::new(bucket(0, HOUR, 1)).is_none());
        assert!(Keyed::<u8>::new(bucket(1, Duration::ZERO, 1)).is_none());
        assert!(Keyed::<u8>::new(bucket(1000, HOUR, MAXIMUM_KEYS)).is_some());
    }

    #[test]
    fn each_key_spends_only_its_own_burst() {
        let keyed = Keyed::new(bucket(2, HOUR, 8)).unwrap();
        assert!(keyed.admit(&1u8));
        assert!(keyed.admit(&1));
        assert!(!keyed.admit(&1));
        assert!(keyed.admit(&2));
    }

    #[test]
    fn an_idle_key_is_evicted_by_pruning() {
        let keyed = Keyed::new(bucket(1, Duration::from_millis(50), 8)).unwrap();
        assert!(keyed.admit(&1u8));
        assert!(keyed.admit(&2));
        assert_eq!(keyed.tracked(), 2);
        std::thread::sleep(Duration::from_millis(150));
        // A key that was just used is not idle.
        assert!(keyed.admit(&2));
        keyed.prune();
        assert_eq!(keyed.tracked(), 1);
        std::thread::sleep(Duration::from_millis(150));
        keyed.prune();
        assert_eq!(keyed.tracked(), 0);
    }

    #[test]
    fn a_full_table_throttles_new_keys_together_without_a_lockout() {
        let keyed = Keyed::new(bucket(2, HOUR, 2)).unwrap();
        // Attacker keys fill the table.
        assert!(keyed.admit(&1u8));
        assert!(keyed.admit(&2));
        // Unknown sources share one overflow bucket of one key's size...
        assert!(keyed.admit(&3));
        assert!(keyed.admit(&4));
        // ...so neither one source nor many new ones can exceed it.
        assert!(!keyed.admit(&5));
        assert!(!keyed.admit(&3));
        assert_eq!(keyed.tracked(), 2);
        // Tracked sources keep their own buckets.
        assert!(keyed.admit(&1));
        assert!(!keyed.admit(&1));
        assert!(keyed.admit(&2));
    }

    #[test]
    fn replenished_keys_make_room_for_new_ones() {
        let keyed = Keyed::new(bucket(1, Duration::from_millis(2), 2)).unwrap();
        assert!(keyed.admit(&1u8));
        assert!(keyed.admit(&2));
        std::thread::sleep(Duration::from_millis(30));
        assert!(keyed.admit(&3));
        assert_eq!(keyed.tracked(), 1);
    }

    #[test]
    fn a_poisoned_table_stays_usable() {
        let keyed = Keyed::new(bucket(1, HOUR, 2)).unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = keyed.table.lock().unwrap();
            panic!("poison");
        }));
        assert!(keyed.table.is_poisoned());
        assert!(keyed.admit(&1u8));
        assert!(!keyed.admit(&1));
    }
}
