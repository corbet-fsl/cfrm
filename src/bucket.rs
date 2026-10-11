//! Bounded in-memory token buckets keyed by a source or session. State lives in
//! RAM only: nothing is logged, persisted or shared with another process.
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use std::{hash::Hash, num::NonZeroU32, time::Duration};

/// Largest accepted key table. The table never grows past its configured bound.
pub const MAXIMUM_KEYS: usize = 1_048_576;

/// One keyed bucket policy: `burst` immediate tokens, one more every
/// `replenish`, at most `keys` live keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bucket {
    pub burst: u32,
    pub replenish: Duration,
    pub keys: usize,
}

pub struct Keyed<K: Hash + Eq + Clone> {
    limiter: DefaultKeyedRateLimiter<K>,
    keys: usize,
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
            limiter: RateLimiter::keyed(quota),
            keys: bucket.keys,
        })
    }

    /// Drop every fully replenished (idle) key. Keys are never logged, printed
    /// or exported: this type has no `Debug` and exposes only a count.
    pub fn prune(&self) {
        self.limiter.retain_recent();
        self.limiter.shrink_to_fit();
    }

    /// Number of keys currently tracked.
    pub fn tracked(&self) -> usize {
        self.limiter.len()
    }

    /// Spend one token. A full table first drops fully replenished keys; when it
    /// is still full every key is refused (fail closed) instead of growing.
    pub fn admit(&self, key: &K) -> bool {
        if self.limiter.len() >= self.keys {
            self.prune();
            if self.limiter.len() >= self.keys {
                return false;
            }
        }
        self.limiter.check_key(key).is_ok()
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

    #[test]
    fn invalid_policies_are_refused() {
        let hour = Duration::from_secs(3600);
        assert!(Keyed::<u8>::new(bucket(1, hour, 0)).is_none());
        assert!(Keyed::<u8>::new(bucket(1, hour, MAXIMUM_KEYS + 1)).is_none());
        assert!(Keyed::<u8>::new(bucket(0, hour, 1)).is_none());
        assert!(Keyed::<u8>::new(bucket(1, Duration::ZERO, 1)).is_none());
        assert!(Keyed::<u8>::new(bucket(1, hour, MAXIMUM_KEYS)).is_some());
    }

    #[test]
    fn each_key_spends_only_its_own_burst() {
        let keyed = Keyed::new(bucket(2, Duration::from_secs(3600), 8)).unwrap();
        assert!(keyed.admit(&1u8));
        assert!(keyed.admit(&1));
        assert!(!keyed.admit(&1));
        assert!(keyed.admit(&2));
    }

    #[test]
    fn an_idle_key_is_evicted_by_pruning() {
        let keyed = Keyed::new(bucket(1, Duration::from_millis(2), 8)).unwrap();
        assert!(keyed.admit(&1u8));
        assert!(keyed.admit(&2));
        assert_eq!(keyed.tracked(), 2);
        keyed.prune();
        // Still limited, so still tracked.
        assert_eq!(keyed.tracked(), 2);
        std::thread::sleep(Duration::from_millis(30));
        keyed.prune();
        assert_eq!(keyed.tracked(), 0);
    }

    #[test]
    fn a_full_table_fails_closed_until_keys_replenish() {
        let hour = Keyed::new(bucket(1, Duration::from_secs(3600), 2)).unwrap();
        assert!(hour.admit(&1u8));
        assert!(hour.admit(&2));
        // Both live keys are still limited, so a new key cannot be tracked.
        assert!(!hour.admit(&3));
        assert!(!hour.admit(&1));

        let quick = Keyed::new(bucket(1, Duration::from_millis(2), 2)).unwrap();
        assert!(quick.admit(&1u8));
        assert!(quick.admit(&2));
        std::thread::sleep(Duration::from_millis(30));
        // Replenished keys are dropped, so the table makes room again.
        assert!(quick.admit(&3));
    }
}
