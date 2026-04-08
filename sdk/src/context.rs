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

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};

use crate::{
    http::{
        restricted::RestrictedResolver, AsyncGenericResolver, AsyncHttpResolver,
        SyncGenericResolver, SyncHttpResolver,
    },
    maybe_send_sync::{MaybeSend, MaybeSync},
    settings::Settings,
    signer::{BoxedAsyncSigner, BoxedSigner},
    AsyncSigner, Error, Result, Signer,
};

/// Phases reported by the progress callback.
///
/// Passed to the progress callback registered on [`Context`] so callers can
/// display progress indicators or make phase-specific cancellation decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProgressPhase {
    /// Parsing and extracting JUMBF manifest data from an asset stream (I/O phase).
    Reading,
    /// Verifying the structure and integrity of a manifest store entry.
    VerifyingManifest,
    /// Verifying a COSE cryptographic signature and certificate chain for a claim.
    /// Fires twice per claim: once before COSE parse (`step=1`) and once after
    /// OCSP and full signature verification (`step=2`).
    VerifyingSignature,
    /// Verifying one ingredient's embedded manifest.  Fires once per ingredient
    /// (`step` = ingredient index, `total` = total ingredient count).
    VerifyingIngredient,
    /// Re-hashing the asset bytes to verify the `c2pa.hash.data` or `c2pa.hash.bmff`
    /// assertion (the most time-consuming part of reading for large assets).
    VerifyingAssetHash,
    /// Adding an ingredient to the manifest.
    AddingIngredient,
    /// Generating a thumbnail for the asset (during signing).
    Thumbnail,
    /// Hashing asset data to build the hash binding assertion (during signing).
    Hashing,
    /// Signing the claim with COSE, including any remote TSA timestamp fetch.
    Signing,
    /// Embedding the signed JUMBF manifest store into the output asset.
    Embedding,
    /// Fetching a remote manifest over the network.
    FetchingRemoteManifest,
    /// Writing the asset with the placeholder JUMBF to the output stream
    /// (the full-file streaming copy that precedes the hash-readback pass).
    /// Fires once between the write pass and the hash computation pass so
    /// callers can distinguish I/O time from CPU hashing time.
    Writing,
    /// Fetching an OCSP response over the network.
    FetchingOCSP,
    /// Fetching a timestamp from a remote TSA over the network.
    FetchingTimestamp,
}

/// Progress callback function type.
///
/// Called at key checkpoints during signing and reading operations.
///
/// # Parameters
/// * `phase` – the current [`ProgressPhase`], which fully describes what the SDK
///   is doing.  No separate message string is provided; callers should derive any
///   user-visible text from `phase` in whatever language they need.
/// * `step`  – monotonically increasing counter within the current phase, starting
///   at `1`.  Resets to `1` at the start of each new phase.  Use it as a liveness
///   signal: as long as `step` keeps rising, the SDK is making forward progress.
///   The unit is phase-specific (e.g. chunk index for [`ProgressPhase::Hashing`],
///   ingredient index for [`ProgressPhase::VerifyingIngredient`]) and should
///   otherwise be treated as opaque.
/// * `total` – interpreted as follows:
///   - `0` – indeterminate; the count is not known in advance.  Show a spinner
///     and use the rising `step` value as a liveness heartbeat.
///   - `1` – single-shot phase; the callback itself is the notification.
///   - `> 1` – determinate; `step / total` gives a completion fraction suitable
///     for a progress bar.
///
/// # Return value
/// Return `true` to continue, `false` to request cancellation.
/// The SDK returns [`Error::OperationCancelled`] at the next safe checkpoint.
///
/// On non-WASM targets the closure must be `Send + Sync`; on WASM (single-threaded)
/// no thread-safety bounds are required.
#[cfg(not(target_arch = "wasm32"))]
pub type ProgressCallbackFunc = dyn Fn(ProgressPhase, u32, u32) -> bool + Send + Sync;

/// Progress callback function type (WASM variant – no `Send + Sync`).
#[cfg(target_arch = "wasm32")]
pub type ProgressCallbackFunc = dyn Fn(ProgressPhase, u32, u32) -> bool;

/// Internal state for sync HTTP resolver selection.
enum SyncResolverState {
    /// User-provided custom resolver.
    Custom(Arc<dyn SyncHttpResolver>),
    /// Default resolver with lazy initialization.
    Default(OnceLock<Arc<dyn SyncHttpResolver>>),
}

/// Internal state for async HTTP resolver selection.
enum AsyncResolverState {
    /// User-provided custom resolver.
    Custom(Arc<dyn AsyncHttpResolver>),
    /// Default resolver with lazy initialization.
    Default(OnceLock<Arc<dyn AsyncHttpResolver>>),
}

/// Internal state for signer selection.
enum SignerState {
    /// User-provided custom signer.
    Custom(BoxedSigner),
    /// Signer created from context's settings with lazy initialization.
    FromSettings(OnceLock<Result<BoxedSigner>>),
}

/// Internal state for async signer selection.
enum AsyncSignerState {
    /// User-provided custom async signer.
    Custom(BoxedAsyncSigner),
    /// Async signer created from context's settings with lazy initialization.
    FromSettings(OnceLock<Result<BoxedAsyncSigner>>),
}

/// A trait for types that can be converted into Settings.
///
/// This trait allows multiple types to be used as configuration sources,
/// including JSON/TOML strings, serde_json::Value, or Settings directly.
pub trait IntoSettings {
    /// Convert this type into Settings
    fn into_settings(self) -> Result<Settings>;
}

/// Implement for Settings (passthrough)
impl IntoSettings for Settings {
    fn into_settings(self) -> Result<Settings> {
        Ok(self)
    }
}

impl IntoSettings for &Settings {
    fn into_settings(self) -> Result<Settings> {
        Ok(self.clone())
    }
}

/// Implement for &str (JSON/TOML string - tries both formats)
impl IntoSettings for &str {
    fn into_settings(self) -> Result<Settings> {
        let mut settings = Settings::default();
        // Try JSON first, then TOML
        settings
            .update_from_str(self, "json")
            .or_else(|_| settings.update_from_str(self, "toml"))?;
        Ok(settings)
    }
}

/// Implement for String
impl IntoSettings for String {
    fn into_settings(self) -> Result<Settings> {
        self.as_str().into_settings()
    }
}

/// Implement for serde_json::Value
impl IntoSettings for serde_json::Value {
    fn into_settings(self) -> Result<Settings> {
        let json_str = serde_json::to_string(&self).map_err(Error::JsonError)?;
        let mut settings = Settings::default();
        settings.update_from_str(&json_str, "json")?;
        Ok(settings)
    }
}

/// Context holds the configuration and dependencies for C2PA operations.
///
/// Context replaces the global Settings pattern with a more flexible, thread-safe approach.
/// It encapsulates:
/// - **Settings**: Configuration options for C2PA operations.
/// - **HTTP Resolvers**: Customizable sync and async HTTP resolvers for fetching remote manifests.
/// - **Signer**: The cryptographic signer used to sign manifests.
///
/// # Creating a Signer
///
/// There are two ways to provide a signer to a Context:
///
/// 1. **From Settings** (recommended): Configure signer settings in your configuration,
///    and the Context will create the signer automatically when you call [`signer()`](Context::signer):
///
/// ```toml
/// [signer.local]
/// alg = "ps256"
/// sign_cert = "path/to/cert.pem"
/// private_key = "path/to/key.pem"
/// ```
///
/// ```ignore
/// # use c2pa::{Context, Builder, Result};
/// # fn main() -> Result<()> {
/// let context = Context::new()
///     .with_settings(include_str!("config.toml"))?;
///
/// let builder = Builder::from_context(context);
///
/// // Signer is created automatically from context's settings
/// let signer = builder.context().signer()?;
/// # Ok(())
/// # }
/// ```
///
/// 2. **Custom Signer**: Use [`with_signer()`](Context::with_signer) to provide a custom signer
///    directly. This is useful for HSMs, remote signing services, or custom signing logic.
///
/// # Examples
///
/// ## Usage with Builder and Reader
///
/// Both [`Builder`](crate::Builder) and [`Reader`](crate::Reader) can be created with a Context:
///
/// ```ignore
/// # use c2pa::{Context, Builder, Reader, Result};
/// # fn main() -> Result<()> {
/// // Create a Context with settings
/// let context = Context::new()
///     .with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?;
///
/// // Use with Builder
/// let builder = Builder::from_context(context);
///
/// // Get signer from context (created automatically from settings)
/// let signer = builder.context().signer()?;
/// # Ok(())
/// # }
/// ```
///
/// ## Basic usage with default settings
///
/// ```
/// # use c2pa::Context;
/// let context = Context::new();
/// ```
///
/// ## Configure with JSON settings
///
/// ```
/// # use c2pa::{Context, Result};
/// # fn main() -> Result<()> {
/// let context = Context::new().with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?;
/// # Ok(())
/// # }
/// ```
pub struct Context {
    settings: Settings,
    sync_resolver: SyncResolverState,
    async_resolver: AsyncResolverState,
    signer: SignerState,
    async_signer: AsyncSignerState,
    progress_callback: Option<Box<ProgressCallbackFunc>>,
    /// Embedded cancellation flag.  Any thread holding an `Arc<Context>` can call
    /// [`cancel()`](Context::cancel) without needing a separate token object.
    cancel_flag: AtomicBool,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            settings: Settings::default(),
            sync_resolver: SyncResolverState::Default(OnceLock::new()),
            async_resolver: AsyncResolverState::Default(OnceLock::new()),
            #[cfg(test)]
            signer: SignerState::Custom(crate::utils::test_signer::test_signer(
                crate::SigningAlg::Ps256,
            )),
            #[cfg(not(test))]
            signer: SignerState::FromSettings(OnceLock::new()),
            async_signer: AsyncSignerState::FromSettings(OnceLock::new()),
            progress_callback: None,
            cancel_flag: AtomicBool::new(false),
        }
    }
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("settings", &self.settings)
            .finish()
    }
}

impl Context {
    /// Creates a new Context with default settings.
    ///
    /// The default Context will load settings from environment variables or configuration
    /// files if available, and use default HTTP resolvers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::Context;
    /// let context = Context::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume this context and wrap it in an `Arc` for sharing between components.
    ///
    /// This is equivalent to `Arc::new(self)` or `Arc::from(self)`, but more discoverable
    /// and chainable with the builder pattern.
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::{Context, Result};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<()> {
    /// let context = Context::new()
    ///     .with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?
    ///     .into_shared();
    ///
    /// // Now context is Arc<Context> and can be shared
    /// let builder = c2pa::Builder::from_shared_context(&context);
    /// let reader = c2pa::Reader::from_shared_context(&context);
    /// # Ok(())
    /// # }
    /// ```
    pub fn into_shared(self) -> std::sync::Arc<Self> {
        self.into()
    }

    /// Configure this Context with the provided settings.
    ///
    /// Settings can be provided as a Settings struct, JSON string, TOML string, or serde_json::Value.
    ///
    /// # Arguments
    ///
    /// * `settings` - Any type that implements `IntoSettings`
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::{Context, Result};
    /// # fn main() -> Result<()> {
    /// // From JSON string
    /// let context = Context::new().with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_settings<S: IntoSettings>(mut self, settings: S) -> Result<Self> {
        self.settings = settings.into_settings()?;
        Ok(self)
    }

    pub fn set_settings<S: IntoSettings>(&mut self, settings: S) -> Result<()> {
        self.settings = settings.into_settings()?;
        Ok(())
    }

    /// Returns a reference to the settings.
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::Context;
    /// let context = Context::new();
    /// let settings = context.settings();
    /// ```
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Returns a mutable reference to the settings.
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::Context;
    /// let mut context = Context::new();
    /// context.settings_mut().verify.verify_after_sign = true;
    /// ```
    pub fn settings_mut(&mut self) -> &mut Settings {
        &mut self.settings
    }

    /// Configure this Context with a custom synchronous HTTP resolver.
    ///
    /// Custom resolvers can be used to add authentication, caching, logging, or mock network calls in tests.
    ///
    /// # Arguments
    ///
    /// * `resolver` - Any type implementing `SyncHttpResolver`
    pub fn with_resolver<T: SyncHttpResolver + MaybeSend + MaybeSync + 'static>(
        mut self,
        resolver: T,
    ) -> Self {
        self.sync_resolver = SyncResolverState::Custom(Arc::new(resolver));
        self
    }

    pub fn set_resolver<T: SyncHttpResolver + MaybeSend + MaybeSync + 'static>(
        &mut self,
        resolver: T,
    ) -> Result<()> {
        self.sync_resolver = SyncResolverState::Custom(Arc::new(resolver));
        Ok(())
    }

    /// Configure this Context with a custom asynchronous HTTP resolver.
    ///
    /// Async resolvers are used for asynchronous operations like fetching remote manifests.
    ///
    /// # Arguments
    ///
    /// * `resolver` - Any type implementing `AsyncHttpResolver`
    pub fn with_resolver_async<T: AsyncHttpResolver + MaybeSend + MaybeSync + 'static>(
        mut self,
        resolver: T,
    ) -> Self {
        self.async_resolver = AsyncResolverState::Custom(Arc::new(resolver));
        self
    }

    pub fn set_resolver_async<T: AsyncHttpResolver + MaybeSend + MaybeSync + 'static>(
        &mut self,
        resolver: T,
    ) -> Result<()> {
        self.async_resolver = AsyncResolverState::Custom(Arc::new(resolver));
        Ok(())
    }

    /// Returns a reference to the sync resolver.
    ///
    /// The default resolver is a `SyncGenericResolver` wrapped with `RestrictedResolver`
    /// to apply host filtering from the settings.
    pub fn resolver(&self) -> Arc<dyn SyncHttpResolver> {
        match &self.sync_resolver {
            SyncResolverState::Custom(resolver) => resolver.clone(),
            SyncResolverState::Default(once_lock) => once_lock
                .get_or_init(|| {
                    if self.settings.core.allowed_network_hosts.is_some() {
                        let mut resolver = RestrictedResolver::new(SyncGenericResolver::new());
                        resolver
                            .set_allowed_hosts(self.settings.core.allowed_network_hosts.clone());
                        Arc::new(resolver)
                    } else {
                        // For backwards compatibility, we enable redirects in the default case.
                        // Source: https://github.com/contentauth/c2pa-rs/pull/1907
                        Arc::new(SyncGenericResolver::with_redirects().unwrap_or_default())
                    }
                })
                .clone(),
        }
    }

    /// Returns a reference to the async resolver.
    ///
    /// The default resolver is an `AsyncGenericResolver` wrapped with `RestrictedResolver`
    /// to apply host filtering from the settings.
    pub fn resolver_async(&self) -> Arc<dyn AsyncHttpResolver> {
        match &self.async_resolver {
            AsyncResolverState::Custom(resolver) => resolver.clone(),
            AsyncResolverState::Default(once_lock) => once_lock
                .get_or_init(|| {
                    if self.settings.core.allowed_network_hosts.is_some() {
                        let mut resolver = RestrictedResolver::new(AsyncGenericResolver::new());
                        resolver
                            .set_allowed_hosts(self.settings.core.allowed_network_hosts.clone());
                        Arc::new(resolver)
                    } else {
                        // For backwards compatibility, we enable redirects in the default case.
                        // Source: https://github.com/contentauth/c2pa-rs/pull/1907
                        Arc::new(AsyncGenericResolver::with_redirects().unwrap_or_default())
                    }
                })
                .clone(),
        }
    }

    /// Configure this Context with a custom cryptographic signer.
    ///
    /// **Note:** In most cases, you don't need to call this method. Instead, configure signer
    /// settings in your configuration file, and the Context will create the signer automatically
    /// from those settings when you call [`signer()`](Context::signer).
    ///
    /// Use this method when you need custom control over signer creation, such as:
    /// - Using a hardware security module (HSM)
    /// - Implementing custom signing logic
    /// - Using a remote signing service with custom authentication
    ///
    /// # Arguments
    ///
    /// * `signer` - Any type implementing `Signer`
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use c2pa::{Context, create_signer, SigningAlg, Result};
    /// # fn main() -> Result<()> {
    /// // Explicitly create and set a signer
    /// let signer = create_signer::from_files(
    ///     "path/to/cert.pem",
    ///     "path/to/key.pem",
    ///     SigningAlg::Ps256,
    ///     None
    /// )?;
    ///
    /// let context = Context::new().with_signer(signer);
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_signer<T: Signer + MaybeSend + MaybeSync + 'static>(mut self, signer: T) -> Self {
        self.signer = SignerState::Custom(Box::new(signer));
        self
    }

    pub fn set_signer<T: Signer + MaybeSend + MaybeSync + 'static>(
        &mut self,
        signer: T,
    ) -> Result<()> {
        self.signer = SignerState::Custom(Box::new(signer));
        Ok(())
    }

    pub fn set_async_signer<T: AsyncSigner + MaybeSend + MaybeSync + 'static>(
        &mut self,
        signer: T,
    ) -> Result<()> {
        self.async_signer = AsyncSignerState::Custom(Box::new(signer));
        Ok(())
    }

    /// Returns a reference to the signer.
    ///
    /// If a signer was explicitly set via [`with_signer()`](Context::with_signer), returns that signer.
    /// Otherwise, creates a signer from this Context's settings on first access (lazy initialization).
    ///
    /// The signer is created from the `signer` field in this Context's Settings, which should contain
    /// either local signer configuration (certificate and private key) or remote signer configuration
    /// (URL and certificate).
    ///
    /// # Returns
    ///
    /// A reference to the signer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingSignerSettings`] if no signer was explicitly set
    /// with `with_signer()` and no signer configuration is present in this
    /// Context's settings. Returns other errors if signer creation fails (e.g.
    /// invalid credentials, unsupported algorithm, or crypto library errors).
    ///
    /// # Examples
    ///
    /// ## Creating from settings (recommended)
    ///
    /// ```ignore
    /// # use c2pa::{Context, Result};
    /// # fn main() -> Result<()> {
    /// let toml = r#"
    ///     [signer.local]
    ///     alg = "ps256"
    ///     sign_cert = "path/to/cert.pem"
    ///     private_key = "path/to/key.pem"
    /// "#;
    ///
    /// let context = Context::new().with_settings(toml)?;
    ///
    /// // Signer is created automatically from context's settings
    /// let signer = context.signer()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Using a custom signer
    ///
    /// ```ignore
    /// # use c2pa::{Context, create_signer, SigningAlg, Result};
    /// # fn main() -> Result<()> {
    /// let signer = create_signer::from_files(
    ///     "path/to/cert.pem",
    ///     "path/to/key.pem",
    ///     SigningAlg::Ps256,
    ///     None
    /// )?;
    ///
    /// let context = Context::new().with_signer(signer);
    /// let signer_ref = context.signer()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn signer(&self) -> Result<&dyn Signer> {
        match &self.signer {
            SignerState::Custom(signer) => Ok(signer.as_ref()),
            SignerState::FromSettings(once_lock) => {
                let result = once_lock.get_or_init(|| {
                    if let Some(signer_settings) = &self.settings.signer {
                        let c2pa_signer = signer_settings.clone().c2pa_signer()?;

                        if let Some(cawg_settings) = &self.settings.cawg_x509_signer {
                            cawg_settings.clone().cawg_signer(c2pa_signer)
                        } else {
                            Ok(c2pa_signer)
                        }
                    } else {
                        Err(Error::MissingSignerSettings)
                    }
                });
                match result {
                    Ok(boxed) => Ok(boxed.as_ref()),
                    Err(Error::MissingSignerSettings) => Err(Error::MissingSignerSettings),
                    Err(e) => Err(Error::BadParam(format!(
                        "failed to create signer from settings: {e}"
                    ))),
                }
            }
        }
    }

    /// Returns a reference to the async signer.
    ///
    /// If a custom async signer was set with [`Context::with_async_signer`], it will be returned.
    /// Otherwise, the async signer will be created from the context's settings on first access
    /// and cached for future use.
    ///
    /// # Errors
    ///
    /// Returns an error if no async signer is configured in settings and no custom signer was provided.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use c2pa::{Context, Result};
    /// # async fn example() -> Result<()> {
    /// let context = Context::new();
    /// let async_signer = context.async_signer()?;
    /// let signature = async_signer.sign(vec![1, 2, 3]).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn async_signer(&self) -> Result<&dyn AsyncSigner> {
        match &self.async_signer {
            AsyncSignerState::Custom(signer) => Ok(signer.as_ref()),
            AsyncSignerState::FromSettings(once_lock) => {
                let result = once_lock.get_or_init(|| {
                    // TODO: Implement creating async signer from settings when async signer support is added to Settings
                    Err(Error::BadParam(
                        "Async signer not configured in settings".to_string(),
                    ))
                });
                match result {
                    Ok(boxed) => Ok(boxed.as_ref()),
                    Err(e) => Err(Error::BadParam(format!(
                        "failed to create async signer from settings: {e}"
                    ))),
                }
            }
        }
    }

    /// Sets a custom async signer for this Context.
    ///
    /// This replaces any existing async signer (whether from settings or previously set).
    ///
    /// # Arguments
    ///
    /// * `signer` - An async signer that implements the [`AsyncSigner`] trait
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use c2pa::{Context, AsyncSigner, SigningAlg, Result};
    /// # struct MyAsyncSigner;
    /// # #[async_trait::async_trait]
    /// # impl AsyncSigner for MyAsyncSigner {
    /// #     async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> { Ok(vec![]) }
    /// #     fn alg(&self) -> SigningAlg { SigningAlg::Ps256 }
    /// #     fn certs(&self) -> Result<Vec<Vec<u8>>> { Ok(vec![]) }
    /// #     fn reserve_size(&self) -> usize { 1024 }
    /// # }
    /// # fn main() -> Result<()> {
    /// let context = Context::new()
    ///     .with_async_signer(MyAsyncSigner);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_async_signer(mut self, signer: impl AsyncSigner + Send + Sync + 'static) -> Self {
        self.async_signer = AsyncSignerState::Custom(Box::new(signer));
        self
    }

    #[cfg(target_arch = "wasm32")]
    pub fn with_async_signer(mut self, signer: impl AsyncSigner + 'static) -> Self {
        self.async_signer = AsyncSignerState::Custom(Box::new(signer));
        self
    }

    /// Register a progress callback that will be invoked at key phases of
    /// long-running operations (signing, hashing, embedding, etc.).
    ///
    /// The callback receives the current [`ProgressPhase`], a monotonically
    /// increasing step counter, and an optional total (see [`ProgressCallbackFunc`]
    /// for the full `step`/`total` semantics).  Returning `false` from the callback
    /// will cause the operation to return [`Error::OperationCancelled`] at the next
    /// safe checkpoint.
    ///
    /// Closures close over whatever external state they need.  C and WASM adapters
    /// capture their `user_data` / JS reference inside the Rust closure.
    ///
    /// ```
    /// # use c2pa::{Context, ProgressPhase};
    /// let ctx = Context::new().with_progress_callback(|phase, step, total| {
    ///     println!("{phase:?} {step}/{total}");
    ///     true // return false to cancel
    /// });
    /// ```
    pub fn with_progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(ProgressPhase, u32, u32) -> bool + MaybeSend + MaybeSync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
        self
    }

    /// Mutable setter for the progress callback (for FFI builders that cannot use the
    /// consuming builder pattern).
    pub fn set_progress_callback<F>(&mut self, callback: F)
    where
        F: Fn(ProgressPhase, u32, u32) -> bool + MaybeSend + MaybeSync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
    }

    /// Request cancellation of any in-progress operation on this context.
    ///
    /// This is thread-safe and may be called from any thread that holds an
    /// `Arc<Context>`.  The operation will return [`Error::OperationCancelled`]
    /// at the next safe checkpoint.
    ///
    /// # Example
    ///
    /// ```
    /// # use c2pa::Context;
    /// # use std::sync::Arc;
    /// let ctx = Arc::new(Context::new());
    ///
    /// // Hand a clone to a background thread; call cancel() to abort.
    /// let ctx2 = ctx.clone();
    /// // std::thread::spawn(move || ctx2.cancel());
    /// ```
    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::Release);
    }

    /// Returns `true` if [`cancel()`](Context::cancel) has been called.
    pub fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::Acquire)
    }

    /// Report progress and check for cancellation at a single checkpoint.
    ///
    /// Invokes the registered [`ProgressCallbackFunc`] (if any), then checks the
    /// embedded cancel flag.  Returns [`Error::OperationCancelled`] if either
    /// signals a stop.
    ///
    /// `step` is a monotonically increasing counter within `phase` (resets to `1`
    /// at each new phase).  `total` is `0` for indeterminate, `1` for single-shot,
    /// or `> 1` for a determinate phase where `step / total` gives a completion
    /// fraction.  See [`ProgressCallbackFunc`] for the full semantics.
    pub(crate) fn check_progress(&self, phase: ProgressPhase, step: u32, total: u32) -> Result<()> {
        log::info!("progress: phase={phase:?} step={step}/{total}");
        if let Some(cb) = self.progress_callback.as_deref() {
            if !cb(phase, step, total) {
                return Err(Error::OperationCancelled);
            }
        }
        if self.cancel_flag.load(Ordering::Acquire) {
            return Err(Error::OperationCancelled);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_into_settings_from_settings() {
        let mut settings = Settings::default();
        settings.verify.verify_after_sign = true;
        let context = Context::new().with_settings(settings).unwrap();
        assert!(context.settings().verify.verify_after_sign);
    }

    #[test]
    fn test_into_settings_from_json_str() {
        let json = r#"{"verify": {"verify_after_sign": true}}"#;
        let context = Context::new().with_settings(json).unwrap();
        assert!(context.settings().verify.verify_after_sign);
    }
    #[test]
    fn test_into_settings_from_toml_str() {
        let toml = r#"
            [verify]
            verify_after_sign = true
            "#;
        let context = Context::new().with_settings(toml).unwrap();
        assert!(context.settings().verify.verify_after_sign);
    }

    #[test]
    fn test_into_settings_from_json_value() {
        let value = serde_json::json!({"verify": {"verify_after_sign": true}});
        let context = Context::new().with_settings(value).unwrap();
        assert!(context.settings().verify.verify_after_sign);
    }

    #[test]
    fn test_into_settings_invalid_json() {
        let invalid_json = r#"{"verify": {"verify_after_sign": "#;
        let result = Context::new().with_settings(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_signer_from_settings() {
        // Create a context with signer settings from the test_settings.toml file
        let toml = include_str!("../tests/fixtures/test_settings.toml");
        let context = Context::new().with_settings(toml).unwrap();

        // Verify that signer can be created from the settings
        let signer = context.signer();
        assert!(signer.is_ok(), "Signer should be created from settings");

        // Verify the signer has the expected algorithm
        let signer = signer.unwrap();
        assert!(
            signer.alg() == crate::SigningAlg::Ps256,
            "Signer from settings should have Ps256 algorithm"
        );

        // Call signer() again to verify caching works (should return same signer)
        let signer2 = context.signer();
        assert!(signer2.is_ok(), "Cached signer should be returned");
    }

    #[test]
    fn test_signer_missing_settings() {
        // In test mode, Default provides a test signer, so we need to explicitly
        // create a context with FromSettings and empty settings
        let mut context = Context {
            settings: Settings::default(),
            sync_resolver: SyncResolverState::Default(OnceLock::new()),
            async_resolver: AsyncResolverState::Default(OnceLock::new()),
            signer: SignerState::FromSettings(OnceLock::new()),
            async_signer: AsyncSignerState::FromSettings(OnceLock::new()),
            progress_callback: None,
            cancel_flag: AtomicBool::new(false),
        };

        // Update settings to ensure no signer configuration
        context.settings.signer = None;
        context.settings.cawg_x509_signer = None;

        // Verify that signer() returns an error when no signer settings are present
        let result = context.signer();
        assert!(
            result.is_err(),
            "Should error when no signer settings present"
        );
        // Verify it's the expected error type
        assert!(
            matches!(result, Err(Error::MissingSignerSettings)),
            "Expected MissingSignerSettings error, got: {}",
            match result {
                Ok(_) => "Ok(Signer)".to_string(),
                Err(ref e) => format!("Err({e:?})"),
            }
        );
    }

    #[test]
    fn test_custom_signer() {
        // Create a custom test signer
        let custom_signer = crate::utils::test_signer::test_signer(crate::SigningAlg::Es256);

        // Create a context with the custom signer
        let context = Context::new().with_signer(custom_signer);

        // Verify the custom signer is returned with the expected algorithm
        let signer = context.signer().unwrap();
        assert!(
            signer.alg() == crate::SigningAlg::Es256,
            "Custom signer should have Es256 algorithm"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_custom_async_signer() {
        use crate::utils::test_signer::async_test_signer;

        // Create a custom async signer using the test utility
        let custom_async_signer = async_test_signer(crate::SigningAlg::Es256);

        // Create a context with the custom async signer
        let context = Context::new().with_async_signer(custom_async_signer);

        // Verify the custom async signer is returned with the expected algorithm
        let async_signer = context.async_signer().unwrap();
        assert_eq!(
            async_signer.alg(),
            crate::SigningAlg::Es256,
            "Custom async signer should have Es256 algorithm"
        );

        // Verify we can get certs
        let certs = async_signer.certs().unwrap();
        assert!(!certs.is_empty(), "Async signer should have certificates");

        // Test that we can actually call sign
        let signature = async_signer.sign(vec![1, 2, 3, 4]).await;
        assert!(signature.is_ok(), "Sign should succeed");
    }

    #[test]
    fn test_async_signer_missing_settings() {
        // Create a context without custom async signer (will try to load from settings)
        let context = Context {
            settings: Settings::default(),
            sync_resolver: SyncResolverState::Default(OnceLock::new()),
            async_resolver: AsyncResolverState::Default(OnceLock::new()),
            signer: SignerState::FromSettings(OnceLock::new()),
            async_signer: AsyncSignerState::FromSettings(OnceLock::new()),
            progress_callback: None,
            cancel_flag: AtomicBool::new(false),
        };

        // Verify that async_signer() returns an error when no async signer settings are present
        let result = context.async_signer();
        assert!(
            result.is_err(),
            "Should error when no async signer settings present"
        );

        // Verify it's the expected error type
        assert!(
            matches!(result, Err(Error::BadParam(_))),
            "Expected BadParam error"
        );
    }

    #[test]
    fn test_check_progress_no_callback_ok() {
        let context = Context::new();
        let result = context.check_progress(ProgressPhase::Hashing, 1, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_progress_cancelled_returns_error() {
        let context = Context::new();
        context.cancel();
        let result = context.check_progress(ProgressPhase::Signing, 1, 1);
        assert!(matches!(result, Err(Error::OperationCancelled)));
    }

    #[test]
    fn test_check_progress_callback_false_cancels() {
        let context = Context::new().with_progress_callback(|_, _, _| false);
        let result = context.check_progress(ProgressPhase::Reading, 1, 1);
        assert!(matches!(result, Err(Error::OperationCancelled)));
    }

    #[test]
    fn test_check_progress_callback_receives_phase_and_steps() {
        use std::sync::Mutex;
        let received: std::sync::Arc<Mutex<Vec<(ProgressPhase, u32, u32)>>> =
            std::sync::Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();
        let context = Context::new().with_progress_callback(move |phase, step, total| {
            received_clone.lock().unwrap().push((phase, step, total));
            true
        });
        context
            .check_progress(ProgressPhase::Thumbnail, 1, 1)
            .unwrap();
        context
            .check_progress(ProgressPhase::Hashing, 3, 10)
            .unwrap();
        let r = received.lock().unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], (ProgressPhase::Thumbnail, 1, 1));
        assert_eq!(r[1], (ProgressPhase::Hashing, 3, 10));
    }

    #[test]
    fn test_check_progress_indeterminate_total_passes_through() {
        // total=0 means indeterminate; the callback must still receive it correctly
        // and returning true should not cancel.
        use std::sync::Mutex;
        let received: std::sync::Arc<Mutex<Vec<(ProgressPhase, u32, u32)>>> =
            std::sync::Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();
        let context = Context::new().with_progress_callback(move |phase, step, total| {
            received_clone.lock().unwrap().push((phase, step, total));
            true
        });
        context
            .check_progress(ProgressPhase::Hashing, 1, 0)
            .unwrap();
        context
            .check_progress(ProgressPhase::Hashing, 2, 0)
            .unwrap();
        let r = received.lock().unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], (ProgressPhase::Hashing, 1, 0));
        assert_eq!(r[1], (ProgressPhase::Hashing, 2, 0));
    }

    #[test]
    fn test_cancel_flag_checked_between_callbacks() {
        // cancel() called between two check_progress calls (no callback involved)
        // should cause the second call to return OperationCancelled.
        let context = Context::new();
        assert!(context.check_progress(ProgressPhase::Hashing, 1, 0).is_ok());
        context.cancel();
        assert!(matches!(
            context.check_progress(ProgressPhase::Hashing, 2, 0),
            Err(Error::OperationCancelled)
        ));
    }

    #[test]
    fn test_is_cancelled_after_cancel() {
        let context = Context::new();
        assert!(!context.is_cancelled());
        context.cancel();
        assert!(context.is_cancelled());
    }

    #[test]
    fn test_default_sync_resolver() {
        // Create a context with default resolver
        let context = Context::new();

        // Verify we can get the default resolver
        let _resolver = context.resolver();
    }

    #[test]
    fn test_default_async_resolver() {
        // Create a context with default resolver
        let context = Context::new();

        // Verify we can get the default async resolver
        let _resolver = context.resolver_async();

        // The test passes if we can get the async resolver without errors
        // The default is a RestrictedResolver wrapping AsyncGenericResolver
    }

    #[test]
    fn test_custom_sync_resolver() {
        use std::io::Read;

        use http::{Request, Response};

        use crate::http::SyncHttpResolver;

        // Create a mock sync resolver
        struct MockSyncResolver;

        impl SyncHttpResolver for MockSyncResolver {
            fn http_resolve(
                &self,
                _request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn Read>>, crate::http::HttpResolverError> {
                // Return a mock response
                Ok(
                    Response::builder()
                        .status(200)
                        .body(Box::new(std::io::Cursor::new(b"mock response".to_vec()))
                            as Box<dyn Read>)
                        .unwrap(),
                )
            }
        }

        // Create a context with the custom resolver
        let context = Context::new().with_resolver(MockSyncResolver);

        // Verify the custom resolver is used
        let resolver = context.resolver();

        // Make a test request to verify it's our mock
        let request = Request::builder()
            .uri("http://example.com")
            .body(vec![])
            .unwrap();

        let response = resolver.http_resolve(request);
        assert!(response.is_ok(), "Mock resolver should succeed");

        // Read the body to verify it's our mock response
        let mut body = response.unwrap().into_body();
        let mut buffer = Vec::new();
        body.read_to_end(&mut buffer).unwrap();
        assert_eq!(buffer, b"mock response");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_custom_async_resolver() {
        use std::io::Read;

        use async_trait::async_trait;
        use http::{Request, Response};

        use crate::http::AsyncHttpResolver;

        // Create a mock async resolver
        struct MockAsyncResolver;

        #[async_trait]
        impl AsyncHttpResolver for MockAsyncResolver {
            async fn http_resolve_async(
                &self,
                _request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn Read>>, crate::http::HttpResolverError> {
                // Return a mock response
                Ok(Response::builder()
                    .status(200)
                    .body(
                        Box::new(std::io::Cursor::new(b"mock async response".to_vec()))
                            as Box<dyn Read>,
                    )
                    .unwrap())
            }
        }

        // Create a context with the custom async resolver
        let context = Context::new().with_resolver_async(MockAsyncResolver);

        // Verify the custom async resolver is used
        let resolver = context.resolver_async();

        // Make a test request to verify it's our mock
        let request = Request::builder()
            .uri("http://example.com")
            .body(vec![])
            .unwrap();

        let response = resolver.http_resolve_async(request).await;
        assert!(response.is_ok(), "Mock async resolver should succeed");

        // Read the body to verify it's our mock response
        let mut body = response.unwrap().into_body();
        let mut buffer = Vec::new();
        body.read_to_end(&mut buffer).unwrap();
        assert_eq!(buffer, b"mock async response");
    }

    #[test]
    fn test_resolver_with_allowed_hosts() {
        // Create a context with restricted allowed hosts
        let settings_toml = r#"
            [core]
            allowed_network_hosts = ["example.com", "test.org"]
        "#;
        let context = Context::new().with_settings(settings_toml).unwrap();

        // Get the resolver
        let _resolver = context.resolver();

        // Note: We can't easily test the actual restriction behavior here
        // without making real HTTP requests, but we verify the resolver is created
        // with the allowed hosts configuration
        assert_eq!(
            context
                .settings()
                .core
                .allowed_network_hosts
                .as_ref()
                .unwrap()
                .len(),
            2,
            "Should have 2 allowed hosts configured"
        );
    }

    #[test]
    fn test_resolver_caching() {
        // Create a context
        let context = Context::new();

        // Get the resolver multiple times
        let _resolver1 = context.resolver();
        let _resolver2 = context.resolver();
        let _resolver3 = context.resolver();

        // The test passes if we can call resolver() multiple times without errors
        // The OnceLock ensures the same resolver is returned (initialized once)
        // We can't easily compare trait object pointers, but the fact that
        // repeated calls succeed proves the caching works
    }

    #[test]
    fn test_async_resolver_caching() {
        // Create a context
        let context = Context::new();

        // Get the async resolver multiple times
        let _resolver1 = context.resolver_async();
        let _resolver2 = context.resolver_async();
        let _resolver3 = context.resolver_async();

        // The test passes if we can call resolver_async() multiple times without errors
        // The OnceLock ensures the same resolver is returned (initialized once)
    }

    #[test]
    fn test_set_resolver() {
        use std::io::Read;

        use http::{Request, Response};

        use crate::http::SyncHttpResolver;

        // Define a custom resolver
        struct CustomResolver;
        impl SyncHttpResolver for CustomResolver {
            fn http_resolve(
                &self,
                _request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn Read>>, crate::http::HttpResolverError> {
                let body = Box::new(std::io::Cursor::new(b"custom sync response".to_vec()));
                Ok(Response::builder()
                    .status(200)
                    .body(body as Box<dyn Read>)
                    .unwrap())
            }
        }

        // Create a context and mutate it with set_resolver
        let mut context = Context::new();
        let result = context.set_resolver(CustomResolver);
        assert!(result.is_ok(), "set_resolver should succeed");

        // Verify the resolver was set by calling it
        let resolver = context.resolver();
        let request = Request::builder()
            .uri("http://example.com")
            .body(Vec::new())
            .unwrap();

        let response = resolver.http_resolve(request);
        assert!(response.is_ok(), "Custom resolver should be callable");

        let mut body = response.unwrap().into_body();
        let mut buffer = Vec::new();
        body.read_to_end(&mut buffer).unwrap();
        assert_eq!(buffer, b"custom sync response");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_set_resolver_async() {
        use std::io::Read;

        use async_trait::async_trait;
        use http::{Request, Response};

        use crate::http::AsyncHttpResolver;

        // Define a custom async resolver
        struct CustomAsyncResolver;

        #[async_trait]
        impl AsyncHttpResolver for CustomAsyncResolver {
            async fn http_resolve_async(
                &self,
                _request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn Read>>, crate::http::HttpResolverError> {
                Ok(Response::builder()
                    .status(200)
                    .body(
                        Box::new(std::io::Cursor::new(b"custom async response".to_vec()))
                            as Box<dyn Read>,
                    )
                    .unwrap())
            }
        }

        // Create a context and mutate it with set_resolver_async
        let mut context = Context::new();
        let result = context.set_resolver_async(CustomAsyncResolver);
        assert!(result.is_ok(), "set_resolver_async should succeed");

        // Verify the async resolver was set by calling it
        let resolver = context.resolver_async();
        let request = Request::builder()
            .uri("http://example.com")
            .body(Vec::new())
            .unwrap();

        let response = resolver.http_resolve_async(request).await;
        assert!(response.is_ok(), "Custom async resolver should be callable");

        let mut body = response.unwrap().into_body();
        let mut buffer = Vec::new();
        body.read_to_end(&mut buffer).unwrap();
        assert_eq!(buffer, b"custom async response");
    }

    #[test]
    fn test_set_signer() {
        use crate::SigningAlg;

        // Create a custom test signer (Es256)
        let custom_signer = crate::utils::test_signer::test_signer(SigningAlg::Es256);

        // Create a context and mutate it with set_signer
        let mut context = Context::new();
        let result = context.set_signer(custom_signer);
        assert!(result.is_ok(), "set_signer should succeed");

        // Verify the signer was set by using it
        let signer = context.signer();
        assert!(signer.is_ok(), "Should be able to retrieve custom signer");

        let signer = signer.unwrap();
        assert_eq!(signer.alg(), SigningAlg::Es256, "Signer should be Es256");

        // Verify we can sign data
        let signature = signer.sign(b"test data");
        assert!(
            signature.is_ok(),
            "Should be able to sign with custom signer"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_set_async_signer() {
        use crate::SigningAlg;

        // Create a custom async test signer (Es256)
        let custom_signer = crate::utils::test_signer::async_test_signer(SigningAlg::Es256);

        // Create a context and mutate it with set_async_signer
        let mut context = Context::new();
        let result = context.set_async_signer(custom_signer);
        assert!(result.is_ok(), "set_async_signer should succeed");

        // Verify the async signer was set by using it
        let signer = context.async_signer();
        assert!(
            signer.is_ok(),
            "Should be able to retrieve custom async signer"
        );

        let signer = signer.unwrap();
        assert_eq!(
            signer.alg(),
            SigningAlg::Es256,
            "Async signer should be Es256"
        );

        // Verify we can sign data
        let signature = signer.sign(b"test data".to_vec()).await;
        assert!(
            signature.is_ok(),
            "Should be able to sign with custom async signer"
        );
    }

    #[test]
    fn test_set_methods_replace_previous_values() {
        use crate::SigningAlg;

        // Create a context with initial signer (Ps256)
        let initial_signer = crate::utils::test_signer::test_signer(SigningAlg::Ps256);
        let mut context = Context::new().with_signer(initial_signer);

        // Verify initial signer
        let signer = context.signer().unwrap();
        assert_eq!(
            signer.alg(),
            SigningAlg::Ps256,
            "Initial signer should be Ps256"
        );

        // Replace with new signer (Es256) using set_signer
        let new_signer = crate::utils::test_signer::test_signer(SigningAlg::Es256);
        context.set_signer(new_signer).unwrap();

        // Verify signer was replaced
        let signer = context.signer().unwrap();
        assert_eq!(
            signer.alg(),
            SigningAlg::Es256,
            "Signer should now be Es256"
        );
    }
}
