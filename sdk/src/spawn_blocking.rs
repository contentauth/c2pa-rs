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

//! Async entry points that run the synchronous engine on Tokio's blocking thread pool, so
//! parsing, hashing, signing, and network requests never stall the caller's executor.

use std::io::{Read, Seek, Write};

use crate::{Builder, Error, Reader, Result, Signer};

async fn spawn_blocking<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let runtime = tokio::runtime::Handle::try_current().map_err(|e| Error::OtherError(e.into()))?;
    match runtime.spawn_blocking(work).await {
        Ok(result) => result,
        Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
        Err(_) => Err(Error::OperationCancelled),
    }
}

impl Reader {
    /// Like [`with_stream`](Reader::with_stream), but runs on Tokio's blocking thread pool.
    ///
    /// The calling task's executor thread is free while the manifest store is read and
    /// validated. Must be awaited within a Tokio runtime; a panic in the engine resumes here.
    #[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
    pub async fn with_stream_spawn_blocking<R>(self, format: &str, stream: R) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let format = format.to_owned();
        spawn_blocking(move || self.with_stream(&format, stream)).await
    }
}

impl Builder {
    /// Like [`sign`](Builder::sign), but runs on Tokio's blocking thread pool.
    ///
    /// Returns the builder, the bytes of the embedded manifest, and `dest`. The calling task's
    /// executor thread is free while the asset is hashed and the manifest signed. Must be
    /// awaited within a Tokio runtime; a panic in the engine resumes here.
    #[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
    pub async fn sign_spawn_blocking<S, R, W>(
        mut self,
        signer: S,
        format: &str,
        mut source: R,
        mut dest: W,
    ) -> Result<(Self, Vec<u8>, W)>
    where
        S: Signer + Send + 'static,
        R: Read + Seek + Send + 'static,
        W: Write + Read + Seek + Send + 'static,
    {
        let format = format.to_owned();
        spawn_blocking(move || {
            let manifest = self.sign(&signer, &format, &mut source, &mut dest)?;
            Ok((self, manifest, dest))
        })
        .await
    }

    /// Like [`save_to_stream`](Builder::save_to_stream), signing with the context's signer, but
    /// runs on Tokio's blocking thread pool.
    ///
    /// Returns the builder, the bytes of the embedded manifest, and `dest`. Must be awaited
    /// within a Tokio runtime; a panic in the engine resumes here.
    #[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
    pub async fn save_to_stream_spawn_blocking<R, W>(
        mut self,
        format: &str,
        mut source: R,
        mut dest: W,
    ) -> Result<(Self, Vec<u8>, W)>
    where
        R: Read + Seek + Send + 'static,
        W: Write + Read + Seek + Send + 'static,
    {
        let format = format.to_owned();
        spawn_blocking(move || {
            let manifest = self.save_to_stream(&format, &mut source, &mut dest)?;
            Ok((self, manifest, dest))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::{
        io::{self, Cursor, SeekFrom},
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc,
        },
        time::Duration,
    };

    use super::*;
    use crate::{utils::test_signer::test_signer, Context, SigningAlg};

    const SIGNED: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
    const UNSIGNED: &[u8] = include_bytes!("../tests/fixtures/no_manifest.jpg");
    const TIMEOUT: Duration = Duration::from_secs(10);
    const CONCURRENT: usize = 16;

    fn definition() -> String {
        serde_json::json!({
            "claim_generator_info": [{ "name": "c2pa_test", "version": "1.0.0" }],
            "title": "Test_Manifest",
            "assertions": [{
                "label": "c2pa.actions",
                "data": {
                    "actions": [{
                        "action": "c2pa.created",
                        "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty",
                    }]
                }
            }]
        })
        .to_string()
    }

    fn builder() -> Builder {
        Builder::from_context(Context::new())
            .with_definition(definition())
            .unwrap()
    }

    /// A stream whose first access parks the engine until the test releases it, and fails if
    /// it is never released (as it would not be, were the engine blocking the runtime thread
    /// that releases it).
    struct Gated<R> {
        inner: R,
        gate: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    }

    struct Gate {
        entered: mpsc::Receiver<()>,
        release: mpsc::Sender<()>,
    }

    fn gated<R>(inner: R) -> (Gated<R>, Gate) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let stream = Gated {
            inner,
            gate: Some((entered_tx, release_rx)),
        };
        let gate = Gate {
            entered: entered_rx,
            release: release_tx,
        };
        (stream, gate)
    }

    impl<R> Gated<R> {
        fn wait(&mut self) -> io::Result<()> {
            if let Some((entered, release)) = self.gate.take() {
                entered.send(()).map_err(io::Error::other)?;
                release.recv_timeout(TIMEOUT).map_err(io::Error::other)?;
            }
            Ok(())
        }
    }

    impl<R: Read> Read for Gated<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.wait()?;
            self.inner.read(buf)
        }
    }

    impl<R: Seek> Seek for Gated<R> {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.wait()?;
            self.inner.seek(pos)
        }
    }

    /// Waits, off the runtime thread, until `count` gated operations are parked inside the engine.
    async fn all_entered(gates: Vec<Gate>) -> Vec<Gate> {
        tokio::task::spawn_blocking(move || {
            for gate in &gates {
                gate.entered.recv_timeout(TIMEOUT).unwrap();
            }
            gates
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn read_round_trips() {
        let reader = Reader::from_context(Context::new())
            .with_stream_spawn_blocking("image/jpeg", Cursor::new(SIGNED))
            .await
            .unwrap();
        assert!(reader.active_manifest().is_some());
    }

    #[tokio::test]
    async fn sign_round_trips_and_returns_builder_and_dest() {
        let (builder, manifest, mut dest) = builder()
            .sign_spawn_blocking(
                test_signer(SigningAlg::Ps256),
                "image/jpeg",
                Cursor::new(UNSIGNED),
                Cursor::new(Vec::new()),
            )
            .await
            .unwrap();
        assert!(!manifest.is_empty());
        assert_eq!(builder.definition.title.as_deref(), Some("Test_Manifest"));

        dest.rewind().unwrap();
        let reader = Reader::from_context(Context::new())
            .with_stream_spawn_blocking("image/jpeg", dest)
            .await
            .unwrap();
        assert_eq!(
            reader.active_manifest().unwrap().title(),
            Some("Test_Manifest")
        );
    }

    #[tokio::test]
    async fn save_to_stream_uses_the_context_signer() {
        let (_, manifest, dest) = builder()
            .save_to_stream_spawn_blocking(
                "image/jpeg",
                Cursor::new(UNSIGNED),
                Cursor::new(Vec::new()),
            )
            .await
            .unwrap();
        assert!(!manifest.is_empty());
        assert!(dest.into_inner().len() > UNSIGNED.len());
    }

    #[tokio::test]
    async fn engine_errors_are_returned() {
        let result = Reader::from_context(Context::new())
            .with_stream_spawn_blocking("image/jpeg", Cursor::new(UNSIGNED))
            .await;
        assert!(matches!(result, Err(Error::JumbfNotFound)));
    }

    #[tokio::test]
    #[should_panic(expected = "engine panic")]
    async fn engine_panics_resume_in_the_caller() {
        spawn_blocking::<(), _>(|| panic!("engine panic"))
            .await
            .unwrap();
    }

    #[test]
    fn outside_a_runtime_is_an_error_not_a_panic() {
        let result = block_on_without_runtime(
            Reader::from_context(Context::new())
                .with_stream_spawn_blocking("image/jpeg", Cursor::new(SIGNED)),
        );
        assert!(matches!(result, Err(Error::OtherError(_))));
    }

    fn block_on_without_runtime<F: std::future::Future>(future: F) -> F::Output {
        use std::{
            pin::pin,
            task::{Context as TaskContext, Poll, Waker},
        };
        let mut future = pin!(future);
        let mut cx = TaskContext::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
            std::thread::yield_now();
        }
    }

    // Stress test: on a single-threaded runtime, many reads and signs are all parked inside the
    // engine at once, while a ticker keeps running on the runtime's only thread and the runtime
    // itself releases them. Were any operation blocking that thread, nothing could release it.
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_operations_never_stall_the_runtime() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let ticker = {
            let ticks = Arc::clone(&ticks);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    ticks.fetch_add(1, Ordering::SeqCst);
                }
            })
        };

        let mut gates = Vec::new();
        let mut reads = tokio::task::JoinSet::new();
        let mut signs = tokio::task::JoinSet::new();
        for i in 0..CONCURRENT {
            if i % 2 == 0 {
                let (stream, gate) = gated(Cursor::new(SIGNED));
                gates.push(gate);
                reads.spawn(
                    Reader::from_context(Context::new())
                        .with_stream_spawn_blocking("image/jpeg", stream),
                );
            } else {
                let (source, gate) = gated(Cursor::new(UNSIGNED));
                gates.push(gate);
                signs.spawn(builder().sign_spawn_blocking(
                    test_signer(SigningAlg::Ps256),
                    "image/jpeg",
                    source,
                    Cursor::new(Vec::new()),
                ));
            }
        }

        let gates = all_entered(gates).await;
        let parked_at = ticks.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            ticks.load(Ordering::SeqCst) > parked_at,
            "the runtime thread stopped ticking while operations were parked"
        );

        for gate in &gates {
            gate.release.send(()).unwrap();
        }
        while let Some(reader) = reads.join_next().await {
            assert!(reader.unwrap().unwrap().active_manifest().is_some());
        }
        while let Some(signed) = signs.join_next().await {
            assert!(!signed.unwrap().unwrap().1.is_empty());
        }
        ticker.abort();
    }
}
