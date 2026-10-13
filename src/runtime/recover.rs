//! Supervision of the maintenance tick. A fenced or failing store is probed
//! again with bounded backoff; a failed tick never ends the service.
use cgth::cmmr::{Clock, State};
use std::future::Future;

/// Most consecutive failures that still lengthen the wait: 2^5 - 1 = 31 skipped
/// ticks between attempts.
const MAXIMUM_DOUBLINGS: u32 = 5;

/// A store handle that can be re-verified after it was fenced `Unavailable`.
pub trait Recover {
    fn state(&self) -> State;
    /// True when the same backend run was reached again and the fence lifted.
    /// A restarted backend is a new incarnation and stays unavailable.
    fn recover(&self) -> impl Future<Output = bool> + Send;
}
impl<C: Clock + Send + Sync, N: cvtl::Network> Recover for cvtl::Volatile<C, N> {
    fn state(&self) -> State {
        cvtl::Store::state(self)
    }
    #[allow(clippy::manual_async_fn)]
    fn recover(&self) -> impl Future<Output = bool> + Send {
        async move { self.reopen().await.is_ok() }
    }
}

#[derive(Default)]
pub struct Backoff {
    failures: u32,
    skip: u32,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Tick {
    /// Waiting out the backoff.
    Waiting,
    Done,
    Failed,
    /// The service owner is missing; there is nothing left to supervise.
    Broken,
}
impl Backoff {
    fn failed(&mut self) -> Tick {
        self.failures = (self.failures + 1).min(MAXIMUM_DOUBLINGS);
        self.skip = (1 << self.failures) - 1;
        Tick::Failed
    }
    /// One maintenance step. `maintain` yields `None` when no owner exists.
    pub async fn tick<S, F, Fut>(&mut self, store: &S, maintain: F) -> Tick
    where
        S: Recover,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Option<bool>>,
    {
        if self.skip > 0 {
            self.skip -= 1;
            return Tick::Waiting;
        }
        if store.state() == State::Unavailable && !store.recover().await {
            return self.failed();
        }
        match maintain().await {
            None => Tick::Broken,
            Some(true) => {
                *self = Self::default();
                Tick::Done
            }
            Some(false) => self.failed(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    struct Store {
        unavailable: AtomicBool,
        recovers: AtomicBool,
        attempts: AtomicU32,
    }
    impl Store {
        fn new(unavailable: bool, recovers: bool) -> Self {
            Self {
                unavailable: AtomicBool::new(unavailable),
                recovers: AtomicBool::new(recovers),
                attempts: AtomicU32::new(0),
            }
        }
    }
    impl Recover for Store {
        fn state(&self) -> State {
            if self.unavailable.load(Ordering::SeqCst) {
                State::Unavailable
            } else {
                State::Ready
            }
        }
        #[allow(clippy::manual_async_fn)]
        fn recover(&self) -> impl Future<Output = bool> + Send {
            async move {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                let ok = self.recovers.load(Ordering::SeqCst);
                if ok {
                    self.unavailable.store(false, Ordering::SeqCst);
                }
                ok
            }
        }
    }

    #[tokio::test]
    async fn a_failed_tick_retries_with_bounded_backoff() {
        let store = Store::new(false, true);
        let mut backoff = Backoff::default();
        assert_eq!(
            backoff.tick(&store, || async { Some(false) }).await,
            Tick::Failed
        );
        // One failure skips exactly one tick, then the next attempt runs.
        assert_eq!(
            backoff.tick(&store, || async { Some(true) }).await,
            Tick::Waiting
        );
        assert_eq!(
            backoff.tick(&store, || async { Some(false) }).await,
            Tick::Failed
        );
        // Two failures skip three ticks.
        for _ in 0..3 {
            assert_eq!(
                backoff.tick(&store, || async { Some(true) }).await,
                Tick::Waiting
            );
        }
        assert_eq!(
            backoff.tick(&store, || async { Some(true) }).await,
            Tick::Done
        );
        // Success forgets the history.
        assert_eq!(
            backoff.tick(&store, || async { Some(false) }).await,
            Tick::Failed
        );
        assert_eq!(
            backoff.tick(&store, || async { Some(true) }).await,
            Tick::Waiting
        );
    }

    #[tokio::test]
    async fn the_wait_is_capped() {
        let store = Store::new(false, true);
        let mut backoff = Backoff::default();
        for _ in 0..20 {
            backoff.skip = 0;
            assert_eq!(
                backoff.tick(&store, || async { Some(false) }).await,
                Tick::Failed
            );
        }
        assert_eq!(backoff.skip, 31);
    }

    #[tokio::test]
    async fn a_fenced_store_is_recovered_before_maintenance() {
        let store = Store::new(true, true);
        let mut backoff = Backoff::default();
        assert_eq!(
            backoff.tick(&store, || async { Some(true) }).await,
            Tick::Done
        );
        assert_eq!(store.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(store.state(), State::Ready);
    }

    #[tokio::test]
    async fn an_unrecoverable_store_backs_off_without_maintaining() {
        let store = Store::new(true, false);
        let mut backoff = Backoff::default();
        let ran = AtomicBool::new(false);
        let flag = &ran;
        let maintain = move || async move {
            flag.store(true, Ordering::SeqCst);
            Some(true)
        };
        assert_eq!(backoff.tick(&store, maintain).await, Tick::Failed);
        assert_eq!(backoff.tick(&store, maintain).await, Tick::Waiting);
        assert!(!ran.load(Ordering::SeqCst));
        assert_eq!(store.attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_missing_owner_ends_supervision() {
        let store = Store::new(false, true);
        let mut backoff = Backoff::default();
        assert_eq!(backoff.tick(&store, || async { None }).await, Tick::Broken);
    }
}
