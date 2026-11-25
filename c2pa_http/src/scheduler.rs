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
    future::Future,
    io::{self, Cursor, Read},
    num::NonZeroUsize,
    panic::{self, AssertUnwindSafe},
    pin::Pin,
    sync::{mpsc, Arc, Condvar, Mutex, PoisonError, Weak},
    task::{Context, Poll, Waker},
    thread,
};

use async_trait::async_trait;
use http::{Request, Response};

use crate::{
    cancel::Cancel, read_body, AsyncHttpResolver, CancellationToken, HttpResolverError,
    MaxResponseBodySize, SyncHttpResolver,
};

type Outcome = Result<Response<Vec<u8>>, HttpResolverError>;
type Callback = Box<dyn FnOnce(Outcome) + Send>;

/// A request's not-yet-invoked callback. Whoever takes it first (the worker, a
/// [`RequestHandle`], or a [`CancellationToken`]) invokes it; everyone else finds it gone.
struct Pending {
    callback: Mutex<Option<Callback>>,
}

impl Pending {
    fn complete(&self, outcome: Outcome) -> bool {
        let callback = self
            .callback
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match callback {
            Some(callback) => {
                callback(outcome);
                true
            }
            None => false,
        }
    }

    fn is_done(&self) -> bool {
        self.callback
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
    }
}

impl Cancel for Pending {
    fn cancel(&self) {
        self.complete(Err(HttpResolverError::Cancelled));
    }
}

struct Job {
    pending: Claim,
    resolver: Arc<dyn SyncHttpResolver>,
    request: Request<Vec<u8>>,
    max_response_body_size: Option<u64>,
}

/// A job's hold on its request: if the job is dropped before completing it (for example while
/// still queued), the callback runs with an error rather than leaving a waiter blocked.
struct Claim(Arc<Pending>);

impl Drop for Claim {
    fn drop(&mut self) {
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            self.0.complete(Err(HttpResolverError::Other(
                "the request was dropped before it completed".into(),
            )))
        }));
    }
}

/// A pool of worker threads that performs HTTP requests on behalf of callers.
///
/// [`submit`](Self::submit) queues a request and returns immediately; a worker runs it through
/// a [`SyncHttpResolver`], reads the response body into memory, and passes the result to a
/// callback. The resolver given to `submit` runs as one unit, so a policy stack such as
/// [`restricted::with_network_policy`](crate::restricted::with_network_policy) checks every
/// redirect hop on the same worker.
///
/// Clones share the same workers. The workers exit once every clone (including those held by
/// [`ScheduledResolver`]s) is dropped and the queue has drained.
#[derive(Clone)]
pub struct RequestScheduler {
    sender: mpsc::Sender<Job>,
    workers: NonZeroUsize,
    max_response_body_size: Option<u64>,
}

impl RequestScheduler {
    /// Starts a scheduler with `workers` threads, the maximum number of requests in flight.
    pub fn new(workers: NonZeroUsize) -> io::Result<Self> {
        let (sender, receiver) = mpsc::channel::<Job>();
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..workers.get() {
            let receiver = Arc::clone(&receiver);
            thread::Builder::new()
                .name(format!("c2pa-http-{index}"))
                .spawn(move || work(&receiver))?;
        }
        Ok(Self {
            sender,
            workers,
            max_response_body_size: None,
        })
    }

    /// Limits the response bodies this handle's submissions accept, failing larger ones with
    /// [`HttpResolverError::ResponseTooLarge`]. The default is no limit. A request's own
    /// [`MaxResponseBodySize`] also applies; the smaller limit wins.
    pub fn with_max_response_body_size(mut self, limit: u64) -> Self {
        self.max_response_body_size = Some(limit);
        self
    }

    /// Queues `request` to be resolved by `resolver` on a worker thread.
    ///
    /// `callback` is invoked exactly once, with the response or the error that ended the
    /// request, normally on the worker thread. If the request is cancelled (through `cancel` or
    /// the returned [`RequestHandle`]) before it completes, `callback` is instead invoked at once
    /// on the cancelling thread with [`HttpResolverError::Cancelled`] — on this thread, if
    /// `cancel` is already cancelled. A request cancelled while queued is never sent; one already
    /// on the wire runs to completion in the background and its result is discarded.
    pub fn submit<F>(
        &self,
        resolver: Arc<dyn SyncHttpResolver>,
        request: Request<Vec<u8>>,
        cancel: Option<&CancellationToken>,
        callback: F,
    ) -> RequestHandle
    where
        F: FnOnce(Result<Response<Vec<u8>>, HttpResolverError>) + Send + 'static,
    {
        let pending = Arc::new(Pending {
            callback: Mutex::new(Some(Box::new(callback))),
        });
        if let Some(token) = cancel {
            token.register(Arc::downgrade(&pending) as Weak<dyn Cancel>);
        }
        let request_limit = request
            .extensions()
            .get::<MaxResponseBodySize>()
            .map(|limit| limit.0);
        let max_response_body_size = match (self.max_response_body_size, request_limit) {
            (Some(scheduler), Some(request)) => Some(scheduler.min(request)),
            (scheduler, request) => scheduler.or(request),
        };
        let job = Job {
            pending: Claim(Arc::clone(&pending)),
            resolver,
            request,
            max_response_body_size,
        };
        if let Err(mpsc::SendError(job)) = self.sender.send(job) {
            job.pending.0.complete(Err(HttpResolverError::Other(
                "the request scheduler has no running workers".into(),
            )));
        }
        RequestHandle { pending }
    }
}

impl fmt::Debug for RequestScheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestScheduler")
            .field("workers", &self.workers)
            .field("max_response_body_size", &self.max_response_body_size)
            .finish_non_exhaustive()
    }
}

fn work(receiver: &Mutex<mpsc::Receiver<Job>>) {
    loop {
        let job = receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv();
        let Ok(Job {
            pending,
            resolver,
            request,
            max_response_body_size,
        }) = job
        else {
            return;
        };
        if pending.0.is_done() {
            continue;
        }
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            read_body(resolver.http_resolve(request)?, max_response_body_size)
        }))
        .unwrap_or_else(|_| {
            Err(HttpResolverError::Other(
                "the http resolver panicked".into(),
            ))
        });
        // A panicking callback must not take the worker down with it.
        let _ = panic::catch_unwind(AssertUnwindSafe(|| pending.0.complete(outcome)));
    }
}

/// A handle to a request queued with [`RequestScheduler::submit`].
///
/// Dropping the handle does not cancel the request.
pub struct RequestHandle {
    pending: Arc<Pending>,
}

impl RequestHandle {
    /// Cancels the request if it has not completed, invoking its callback with
    /// [`HttpResolverError::Cancelled`]. Returns `true` if this call cancelled it.
    pub fn cancel(&self) -> bool {
        self.pending.complete(Err(HttpResolverError::Cancelled))
    }

    /// Returns `true` once the request's callback has been invoked (or is being invoked).
    pub fn is_finished(&self) -> bool {
        self.pending.is_done()
    }
}

impl fmt::Debug for RequestHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestHandle")
            .field("finished", &self.is_finished())
            .finish()
    }
}

/// A one-shot slot filled by a request callback, waited on by blocking or by awaiting.
#[derive(Default)]
struct Slot {
    state: Mutex<SlotState>,
    filled: Condvar,
}

#[derive(Default)]
struct SlotState {
    outcome: Option<Outcome>,
    waker: Option<Waker>,
}

impl Slot {
    fn fill(&self, outcome: Outcome) {
        let waker = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.outcome = Some(outcome);
            state.waker.take()
        };
        self.filled.notify_all();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn wait(&self) -> Outcome {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(outcome) = state.outcome.take() {
                return outcome;
            }
            state = self
                .filled
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// Awaits a submitted request, cancelling it if dropped first.
struct ResponseFuture {
    slot: Arc<Slot>,
    handle: RequestHandle,
}

impl Future for ResponseFuture {
    type Output = Outcome;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Outcome> {
        let mut state = self
            .slot
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(outcome) = state.outcome.take() {
            return Poll::Ready(outcome);
        }
        match &mut state.waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            waker => *waker = Some(cx.waker().clone()),
        }
        Poll::Pending
    }
}

impl Drop for ResponseFuture {
    fn drop(&mut self) {
        self.handle.cancel();
    }
}

/// Resolves requests through a [`RequestScheduler`], as both a [`SyncHttpResolver`] (blocking
/// until the response arrives) and an [`AsyncHttpResolver`] (awaiting it without blocking).
///
/// Every request runs `inner` on a scheduler worker. If a [`CancellationToken`] is attached,
/// cancelling it ends each outstanding request at once with [`HttpResolverError::Cancelled`];
/// dropping an async request's future cancels that request.
///
/// Do not call the blocking resolver from a scheduler worker (for example from inside another
/// resolver it runs): with every worker waiting, nothing would run the request.
#[derive(Clone)]
pub struct ScheduledResolver {
    scheduler: RequestScheduler,
    inner: Arc<dyn SyncHttpResolver>,
    cancel: Option<CancellationToken>,
}

impl ScheduledResolver {
    /// Creates a resolver that runs `inner` on `scheduler`'s workers.
    pub fn new(scheduler: RequestScheduler, inner: Arc<dyn SyncHttpResolver>) -> Self {
        Self {
            scheduler,
            inner,
            cancel: None,
        }
    }

    /// Cancels this resolver's outstanding requests when `token` is cancelled.
    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.cancel = Some(token);
        self
    }

    fn submit(&self, request: Request<Vec<u8>>) -> ResponseFuture {
        let slot = Arc::new(Slot::default());
        let filler = Arc::clone(&slot);
        let handle = self.scheduler.submit(
            Arc::clone(&self.inner),
            request,
            self.cancel.as_ref(),
            move |outcome| filler.fill(outcome),
        );
        ResponseFuture { slot, handle }
    }
}

impl fmt::Debug for ScheduledResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScheduledResolver")
            .field("scheduler", &self.scheduler)
            .field("cancel", &self.cancel)
            .finish_non_exhaustive()
    }
}

fn into_streaming(outcome: Outcome) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
    Ok(outcome?.map(|body| Box::new(Cursor::new(body)) as Box<dyn Read>))
}

impl SyncHttpResolver for ScheduledResolver {
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        let pending = self.submit(request);
        into_streaming(pending.slot.wait())
    }
}

#[async_trait]
impl AsyncHttpResolver for ScheduledResolver {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        into_streaming(self.submit(request).await)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Barrier,
        },
        time::Duration,
    };

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(10);

    fn scheduler(workers: usize) -> RequestScheduler {
        RequestScheduler::new(NonZeroUsize::new(workers).unwrap()).unwrap()
    }

    fn get() -> Request<Vec<u8>> {
        Request::get("http://example.test/")
            .body(Vec::new())
            .unwrap()
    }

    fn body(response: Response<Box<dyn Read>>) -> Vec<u8> {
        let mut buf = Vec::new();
        response.into_body().read_to_end(&mut buf).unwrap();
        buf
    }

    /// Answers with a fixed body after counting the call.
    struct Echo {
        calls: AtomicUsize,
        body: &'static [u8],
        content_length: Option<&'static str>,
    }

    impl Echo {
        fn new(body: &'static [u8]) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                body,
                content_length: None,
            })
        }
    }

    impl SyncHttpResolver for Echo {
        fn http_resolve(
            &self,
            _request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut response = Response::builder().status(200);
            if let Some(len) = self.content_length {
                response = response.header(http::header::CONTENT_LENGTH, len);
            }
            Ok(response.body(Box::new(Cursor::new(self.body)) as Box<dyn Read>)?)
        }
    }

    /// Blocks every request until released, so tests control when workers are busy.
    struct Gate {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    fn gate() -> (Arc<Gate>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let gate = Arc::new(Gate {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        });
        (gate, entered_rx, release_tx)
    }

    impl SyncHttpResolver for Gate {
        fn http_resolve(
            &self,
            _request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv_timeout(TIMEOUT).unwrap();
            Ok(Response::new(
                Box::new(Cursor::new(b"late".to_vec())) as Box<dyn Read>
            ))
        }
    }

    struct Panics;

    impl SyncHttpResolver for Panics {
        fn http_resolve(
            &self,
            _request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            panic!("resolver failure");
        }
    }

    fn submit_and_wait(
        scheduler: &RequestScheduler,
        resolver: Arc<dyn SyncHttpResolver>,
        cancel: Option<&CancellationToken>,
    ) -> (RequestHandle, mpsc::Receiver<Outcome>) {
        let (tx, rx) = mpsc::channel();
        let handle = scheduler.submit(resolver, get(), cancel, move |outcome| {
            tx.send(outcome).unwrap();
        });
        (handle, rx)
    }

    #[test]
    fn submit_invokes_callback_with_buffered_response() {
        let scheduler = scheduler(1);
        let (handle, rx) = submit_and_wait(&scheduler, Echo::new(b"abc"), None);
        let response = rx.recv_timeout(TIMEOUT).unwrap().unwrap();
        assert_eq!(response.into_body(), b"abc");
        assert!(handle.is_finished());
        assert!(!handle.cancel());
        assert!(format!("{handle:?}").contains("finished: true"));
    }

    #[test]
    fn requests_run_concurrently_up_to_the_worker_count() {
        let scheduler = scheduler(3);
        let barrier = Arc::new(Barrier::new(3));

        struct Rendezvous(Arc<Barrier>);
        impl SyncHttpResolver for Rendezvous {
            fn http_resolve(
                &self,
                _request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
                // Only returns once three requests are in flight at the same time.
                self.0.wait();
                Ok(Response::new(Box::new(io::empty()) as Box<dyn Read>))
            }
        }

        let resolver: Arc<dyn SyncHttpResolver> = Arc::new(Rendezvous(barrier));
        let receivers: Vec<_> = (0..3)
            .map(|_| submit_and_wait(&scheduler, Arc::clone(&resolver), None).1)
            .collect();
        for rx in receivers {
            assert!(rx.recv_timeout(TIMEOUT).unwrap().is_ok());
        }
    }

    #[test]
    fn body_limit_rejects_oversized_responses() {
        let scheduler = scheduler(1).with_max_response_body_size(3);

        let (_, rx) = submit_and_wait(&scheduler, Echo::new(b"abcd"), None);
        assert!(matches!(
            rx.recv_timeout(TIMEOUT).unwrap(),
            Err(HttpResolverError::ResponseTooLarge)
        ));

        let lying = Arc::new(Echo {
            calls: AtomicUsize::new(0),
            body: b"ab",
            content_length: Some("1000"),
        });
        let (_, rx) = submit_and_wait(&scheduler, lying, None);
        assert!(matches!(
            rx.recv_timeout(TIMEOUT).unwrap(),
            Err(HttpResolverError::ResponseTooLarge)
        ));

        let (_, rx) = submit_and_wait(&scheduler, Echo::new(b"abc"), None);
        assert_eq!(
            rx.recv_timeout(TIMEOUT).unwrap().unwrap().into_body(),
            b"abc"
        );
    }

    #[test]
    fn resolver_panic_becomes_an_error_and_the_worker_survives() {
        let scheduler = scheduler(1);
        let (_, rx) = submit_and_wait(&scheduler, Arc::new(Panics), None);
        assert!(matches!(
            rx.recv_timeout(TIMEOUT).unwrap(),
            Err(HttpResolverError::Other(_))
        ));

        let (_, rx) = submit_and_wait(&scheduler, Echo::new(b"ok"), None);
        assert!(rx.recv_timeout(TIMEOUT).unwrap().is_ok());
    }

    #[test]
    fn callback_panic_does_not_kill_the_worker() {
        let scheduler = scheduler(1);
        scheduler.submit(Echo::new(b""), get(), None, |_| panic!("callback failure"));
        let (_, rx) = submit_and_wait(&scheduler, Echo::new(b"ok"), None);
        assert!(rx.recv_timeout(TIMEOUT).unwrap().is_ok());
    }

    #[test]
    fn token_cancels_every_request_when_one_callback_panics() {
        let scheduler = scheduler(1);
        let token = CancellationToken::new();
        let (gate, entered, release) = gate();
        let (_, busy) = submit_and_wait(&scheduler, gate, None);
        entered.recv_timeout(TIMEOUT).unwrap();

        scheduler.submit(Echo::new(b""), get(), Some(&token), |_| {
            panic!("callback failure")
        });
        let (_, rx) = submit_and_wait(&scheduler, Echo::new(b""), Some(&token));
        let cancelled = panic::catch_unwind(AssertUnwindSafe(|| token.cancel()));

        assert!(cancelled.is_err());
        assert!(matches!(
            rx.recv_timeout(TIMEOUT).unwrap(),
            Err(HttpResolverError::Cancelled)
        ));
        release.send(()).unwrap();
        busy.recv_timeout(TIMEOUT).unwrap().unwrap();
    }

    #[test]
    fn request_body_limit_stops_reading_an_endless_body() {
        struct Endless(Arc<AtomicUsize>);

        impl SyncHttpResolver for Endless {
            fn http_resolve(
                &self,
                _request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
                let read = Arc::clone(&self.0);
                let body = io::repeat(b'x').take(u64::MAX);
                Ok(Response::new(Box::new(Counted(body, read)) as Box<dyn Read>))
            }
        }

        struct Counted<R>(R, Arc<AtomicUsize>);

        impl<R: Read> Read for Counted<R> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let n = self.0.read(buf)?;
                self.1.fetch_add(n, Ordering::SeqCst);
                Ok(n)
            }
        }

        let read = Arc::new(AtomicUsize::new(0));
        let request = Request::get("http://example.test/")
            .extension(MaxResponseBodySize(1024))
            .body(Vec::new())
            .unwrap();
        let (tx, rx) = mpsc::channel();
        scheduler(1).submit(
            Arc::new(Endless(Arc::clone(&read))),
            request,
            None,
            move |outcome| tx.send(outcome).unwrap(),
        );
        assert!(matches!(
            rx.recv_timeout(TIMEOUT).unwrap(),
            Err(HttpResolverError::ResponseTooLarge)
        ));
        assert_eq!(read.load(Ordering::SeqCst), 1025);
    }

    #[test]
    fn the_smaller_of_the_request_and_scheduler_limits_applies() {
        for (scheduler_limit, request_limit, ok) in [
            (None, Some(2), false),
            (Some(2), Some(10), false),
            (Some(10), Some(2), false),
            (Some(10), Some(3), true),
            (Some(3), None, true),
        ] {
            let mut scheduler = scheduler(1);
            if let Some(limit) = scheduler_limit {
                scheduler = scheduler.with_max_response_body_size(limit);
            }
            let mut request = Request::get("http://example.test/");
            if let Some(limit) = request_limit {
                request = request.extension(MaxResponseBodySize(limit));
            }
            let (tx, rx) = mpsc::channel();
            scheduler.submit(
                Echo::new(b"abc"),
                request.body(Vec::new()).unwrap(),
                None,
                move |outcome| tx.send(outcome).unwrap(),
            );
            let outcome = rx.recv_timeout(TIMEOUT).unwrap();
            assert_eq!(
                outcome.is_ok(),
                ok,
                "{scheduler_limit:?} / {request_limit:?}: {outcome:?}"
            );
        }
    }

    #[test]
    fn maximum_body_limit_does_not_overflow() {
        let scheduler = scheduler(1).with_max_response_body_size(u64::MAX);
        let (_, rx) = submit_and_wait(&scheduler, Echo::new(b"body"), None);
        assert_eq!(
            rx.recv_timeout(TIMEOUT).unwrap().unwrap().into_body(),
            b"body"
        );
    }

    #[test]
    fn cancelling_a_queued_request_skips_it() {
        let scheduler = scheduler(1);
        let (gate, entered, release) = gate();
        let (_, busy) = submit_and_wait(&scheduler, gate, None);
        entered.recv_timeout(TIMEOUT).unwrap();

        let queued = Echo::new(b"never");
        let (handle, rx) = submit_and_wait(&scheduler, queued.clone(), None);
        assert!(handle.cancel());
        assert!(matches!(
            rx.recv_timeout(TIMEOUT).unwrap(),
            Err(HttpResolverError::Cancelled)
        ));

        release.send(()).unwrap();
        busy.recv_timeout(TIMEOUT).unwrap().unwrap();
        // The worker is now free; a later request proves the cancelled one was skipped.
        let (_, rx) = submit_and_wait(&scheduler, Echo::new(b"after"), None);
        rx.recv_timeout(TIMEOUT).unwrap().unwrap();
        assert_eq!(queued.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn token_cancels_an_in_flight_request_and_discards_its_result() {
        let scheduler = scheduler(1);
        let token = CancellationToken::new();
        let (gate, entered, release) = gate();
        let (handle, rx) = submit_and_wait(&scheduler, gate, Some(&token));
        entered.recv_timeout(TIMEOUT).unwrap();

        token.cancel();
        assert!(matches!(
            rx.recv_timeout(TIMEOUT).unwrap(),
            Err(HttpResolverError::Cancelled)
        ));
        assert!(handle.is_finished());

        release.send(()).unwrap();
        // The late response is discarded rather than delivered a second time.
        let (_, after) = submit_and_wait(&scheduler, Echo::new(b""), None);
        after.recv_timeout(TIMEOUT).unwrap().unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn already_cancelled_token_completes_on_the_submitting_thread() {
        let scheduler = scheduler(1);
        let token = CancellationToken::new();
        token.cancel();
        let resolver = Echo::new(b"never");
        let (_, rx) = submit_and_wait(&scheduler, resolver.clone(), Some(&token));
        assert!(matches!(
            rx.try_recv(),
            Ok(Err(HttpResolverError::Cancelled))
        ));

        let (_, rx) = submit_and_wait(&scheduler, Echo::new(b""), None);
        rx.recv_timeout(TIMEOUT).unwrap().unwrap();
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn scheduled_resolver_blocking_path() {
        let resolver = ScheduledResolver::new(scheduler(2), Echo::new(b"sync"));
        assert_eq!(body(resolver.http_resolve(get()).unwrap()), b"sync");
        assert!(format!("{resolver:?}").contains("ScheduledResolver"));
    }

    #[test]
    fn scheduled_resolver_blocking_path_is_released_by_cancellation() {
        let token = CancellationToken::new();
        let (gate, entered, release) = gate();
        let resolver = ScheduledResolver::new(scheduler(1), gate).with_cancellation(token.clone());

        let waiter = thread::spawn(move || resolver.http_resolve(get()).map(body));
        entered.recv_timeout(TIMEOUT).unwrap();
        token.cancel();
        assert!(matches!(
            waiter.join().unwrap(),
            Err(HttpResolverError::Cancelled)
        ));
        release.send(()).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scheduled_resolver_async_path() {
        let resolver = ScheduledResolver::new(scheduler(2), Echo::new(b"async"));
        let response = resolver.http_resolve_async(get()).await.unwrap();
        assert_eq!(body(response), b"async");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_path_never_blocks_the_runtime() {
        // A single-threaded runtime: if awaiting the request blocked the thread, the ticker
        // below could not run until the request finished, and would never release it.
        let (gate, entered, release) = gate();
        let resolver = ScheduledResolver::new(scheduler(1), gate);
        let request =
            tokio::spawn(async move { resolver.http_resolve_async(get()).await.map(body) });

        let ticker = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || entered.recv_timeout(TIMEOUT))
                .await
                .unwrap()
                .unwrap();
            release.send(()).unwrap();
        });

        ticker.await.unwrap();
        assert_eq!(request.await.unwrap().unwrap(), b"late");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_the_async_future_cancels_the_request() {
        let scheduler = scheduler(1);
        let (gate, entered, release) = gate();
        let (_, busy) = submit_and_wait(&scheduler, gate, None);
        tokio::task::spawn_blocking(move || entered.recv_timeout(TIMEOUT))
            .await
            .unwrap()
            .unwrap();

        let queued = Echo::new(b"never");
        let resolver = ScheduledResolver::new(scheduler.clone(), queued.clone());
        let timed_out = tokio::time::timeout(
            Duration::from_millis(20),
            resolver.http_resolve_async(get()),
        )
        .await;
        assert!(timed_out.is_err());

        release.send(()).unwrap();
        tokio::task::spawn_blocking(move || {
            busy.recv_timeout(TIMEOUT).unwrap().unwrap();
            let (_, after) = submit_and_wait(&scheduler, Echo::new(b""), None);
            after.recv_timeout(TIMEOUT).unwrap().unwrap();
        })
        .await
        .unwrap();
        assert_eq!(queued.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_job_dropped_before_it_runs_releases_its_waiter() {
        // A scheduler with no workers: the test holds the queue and drops the job itself.
        let (sender, queue) = mpsc::channel();
        let scheduler = RequestScheduler {
            sender,
            workers: NonZeroUsize::MIN,
            max_response_body_size: None,
        };
        let resolver = ScheduledResolver::new(scheduler, Echo::new(b"never"));
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || tx.send(resolver.http_resolve(get()).map(body)).unwrap());

        drop(queue.recv_timeout(TIMEOUT).unwrap());
        assert!(matches!(
            rx.recv_timeout(TIMEOUT).unwrap(),
            Err(HttpResolverError::Other(_))
        ));
    }

    #[test]
    fn scheduler_debug_reports_configuration() {
        let scheduler = scheduler(2).with_max_response_body_size(7);
        let debug = format!("{scheduler:?}");
        assert!(debug.contains("workers: 2"));
        assert!(debug.contains("Some(7)"));
    }
}
