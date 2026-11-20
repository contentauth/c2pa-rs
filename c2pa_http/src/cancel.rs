// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use std::{
    fmt,
    panic::{self, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, PoisonError, Weak,
    },
};

/// Something that can be aborted when a [`CancellationToken`] is cancelled.
pub(crate) trait Cancel: Send + Sync {
    fn cancel(&self);
}

/// A shareable flag that, once cancelled, aborts every request registered with it.
///
/// Clones share state. Cancellation is permanent.
#[derive(Clone, Default)]
pub struct CancellationToken {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    cancelled: AtomicBool,
    listeners: Mutex<Vec<Weak<dyn Cancel>>>,
}

impl CancellationToken {
    /// Creates a token that has not been cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels the token, aborting every request registered with it.
    ///
    /// Every request is cancelled even if one's callback panics; the first such panic then resumes.
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        let listeners = std::mem::take(
            &mut *self
                .inner
                .listeners
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        let mut first_panic = None;
        for listener in listeners.iter().filter_map(Weak::upgrade) {
            if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| listener.cancel())) {
                first_panic.get_or_insert(payload);
            }
        }
        if let Some(payload) = first_panic {
            panic::resume_unwind(payload);
        }
    }

    /// Returns `true` once [`cancel`](Self::cancel) has been called on this token or a clone.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Registers `listener` to be cancelled with this token, or cancels it now if the token
    /// already is.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn register(&self, listener: Weak<dyn Cancel>) {
        {
            let mut listeners = self
                .inner
                .listeners
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            // `cancel` sets the flag before draining, so checking it under the lock cannot miss
            // a concurrent cancellation.
            if !self.is_cancelled() {
                listeners.retain(|l| l.strong_count() > 0);
                listeners.push(listener);
                return;
            }
        }
        if let Some(listener) = listener.upgrade() {
            listener.cancel();
        }
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[derive(Default)]
    struct Counter(AtomicUsize);

    impl Cancel for Counter {
        fn cancel(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn count(counter: &Counter) -> usize {
        counter.0.load(Ordering::SeqCst)
    }

    #[test]
    fn cancel_is_shared_by_clones_and_permanent() {
        let token = CancellationToken::new();
        let clone = token.clone();
        assert!(!token.is_cancelled());
        clone.cancel();
        assert!(token.is_cancelled());
        assert!(clone.is_cancelled());
        assert_eq!(
            format!("{token:?}"),
            "CancellationToken { cancelled: true }"
        );
    }

    #[test]
    fn cancel_notifies_live_listeners_once() {
        let token = CancellationToken::new();
        let live = Arc::new(Counter::default());
        token.register(Arc::downgrade(&live) as Weak<dyn Cancel>);
        let dropped = Arc::new(Counter::default());
        token.register(Arc::downgrade(&dropped) as Weak<dyn Cancel>);
        drop(dropped);

        token.cancel();
        token.cancel();
        assert_eq!(count(&live), 1);
    }

    #[test]
    fn register_after_cancel_cancels_immediately() {
        let token = CancellationToken::new();
        token.cancel();
        let late = Arc::new(Counter::default());
        token.register(Arc::downgrade(&late) as Weak<dyn Cancel>);
        assert_eq!(count(&late), 1);
    }

    #[test]
    fn register_prunes_dropped_listeners() {
        let token = CancellationToken::new();
        for _ in 0..100 {
            let listener = Arc::new(Counter::default());
            token.register(Arc::downgrade(&listener) as Weak<dyn Cancel>);
        }
        let len = token
            .inner
            .listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        assert_eq!(len, 1);
    }

    #[test]
    fn a_panicking_listener_does_not_stop_the_others() {
        struct Panics;

        impl Cancel for Panics {
            #[allow(clippy::panic)]
            fn cancel(&self) {
                panic!("listener failure");
            }
        }

        let token = CancellationToken::new();
        let before = Arc::new(Counter::default());
        let panics = Arc::new(Panics);
        let after = Arc::new(Counter::default());
        token.register(Arc::downgrade(&before) as Weak<dyn Cancel>);
        token.register(Arc::downgrade(&panics) as Weak<dyn Cancel>);
        token.register(Arc::downgrade(&after) as Weak<dyn Cancel>);

        let cancelled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| token.cancel()));
        assert!(cancelled.is_err(), "the listener's panic is re-raised");
        assert_eq!(count(&before), 1);
        assert_eq!(count(&after), 1);
    }
}
