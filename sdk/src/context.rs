use std::sync::OnceLock;

use crate::{
    http::{
        restricted::RestrictedResolver, AsyncGenericResolver, AsyncHttpResolver,
        SyncGenericResolver, SyncHttpResolver,
    },
    settings::Settings,
    AsyncSigner, Error, Result, Signer,
};

// Type aliases for boxed trait objects with conditional Send + Sync bounds
// These use cfg attributes because MaybeSend/MaybeSync can't be used as
// trait object bounds - the compiler can't verify them for dyn Trait
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedSigner = Box<dyn Signer + Send + Sync>;
#[cfg(target_arch = "wasm32")]
pub type BoxedSigner = Box<dyn Signer>;

#[cfg(not(target_arch = "wasm32"))]
type BoxedSyncResolver = Box<dyn SyncHttpResolver + Send + Sync>;
#[cfg(target_arch = "wasm32")]
type BoxedSyncResolver = Box<dyn SyncHttpResolver>;

#[cfg(not(target_arch = "wasm32"))]
type BoxedAsyncResolver = Box<dyn AsyncHttpResolver + Send + Sync>;
#[cfg(target_arch = "wasm32")]
type BoxedAsyncResolver = Box<dyn AsyncHttpResolver>;

/// Internal state for sync HTTP resolver selection.
enum SyncResolverState {
    /// User-provided custom resolver.
    Custom(BoxedSyncResolver),
    /// Default resolver with lazy initialization.
    Default(OnceLock<RestrictedResolver<SyncGenericResolver>>),
}

/// Internal state for async HTTP resolver selection.
enum AsyncResolverState {
    /// User-provided custom resolver.
    Custom(BoxedAsyncResolver),
    /// Default resolver with lazy initialization.
    Default(OnceLock<RestrictedResolver<AsyncGenericResolver>>),
}

/// Internal state for signer selection.
enum SignerState {
    /// User-provided custom signer.
    Custom(BoxedSigner),
    /// Signer created from context's settings with lazy initialization.
    /// The Result is cached so we only attempt creation once.
    FromSettings(OnceLock<Result<BoxedSigner>>),
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
/// - **Settings**: Configuration options for C2PA operations
/// - **HTTP Resolvers**: Customizable sync and async HTTP resolvers for fetching remote manifests
/// - **Signer**: The cryptographic signer used to sign manifests
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
/// # Usage with Builder and Reader
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
/// # Examples
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
///
/// ## Configure with TOML settings
///
/// ```
/// # use c2pa::{Context, Result};
/// # fn main() -> Result<()> {
/// let toml = r#"
///     [verify]
///     verify_after_sign = true
/// "#;
/// let context = Context::new().with_settings(toml)?;
/// # Ok(())
/// # }
/// ```
pub struct Context {
    settings: Settings,
    sync_resolver: SyncResolverState,
    async_resolver: AsyncResolverState,
    signer: SignerState,
    _signer_async: Option<Box<dyn AsyncSigner>>,
}

// SAFETY: Context is Send + Sync on non-WASM targets.
//
// Rust's compiler cannot automatically prove Send + Sync for Context because it contains
// enum variants with trait objects (Box<dyn Trait>). The compiler conservatively assumes
// these might not be Send + Sync even though we've explicitly added those bounds via cfg.
//
// This manual implementation is safe because ALL fields are Send + Sync on non-WASM:
//
// 1. `settings: Settings`
//    - Derived Send + Sync (contains only Send + Sync types)
//
// 2. `sync_resolver: SyncResolverState`
//    - Custom(Box<dyn SyncHttpResolver + Send + Sync>) - explicitly bounded on non-WASM
//    - Default(OnceLock<RestrictedResolver<T>>) - Send + Sync when T is Send + Sync
//
// 3. `async_resolver: AsyncResolverState`
//    - Custom(Box<dyn AsyncHttpResolver + Send + Sync>) - explicitly bounded on non-WASM
//    - Default(OnceLock<RestrictedResolver<T>>) - Send + Sync when T is Send + Sync
//
// 4. `signer: SignerState`
//    - Custom(Box<dyn Signer + Send + Sync>) - explicitly bounded on non-WASM
//    - FromSettings(OnceLock<Result<Box<dyn Signer + Send + Sync>>>) - explicitly bounded on non-WASM
//
// 5. `_signer_async: Option<Box<dyn AsyncSigner>>`
//    - Currently unused field for future async signer support
//
// These impls enable Arc<Context> to be shared across threads without Clippy warnings,
// which is the intended use case for multi-threaded applications and FFI scenarios.
//
// On WASM targets, these impls are not needed as WASM is single-threaded.
#[cfg(not(target_arch = "wasm32"))]
unsafe impl Send for Context {}

#[cfg(not(target_arch = "wasm32"))]
unsafe impl Sync for Context {}

impl Default for Context {
    fn default() -> Self {
        Self {
            settings: crate::settings::get_settings().unwrap_or_default(),
            sync_resolver: SyncResolverState::Default(OnceLock::new()),
            async_resolver: AsyncResolverState::Default(OnceLock::new()),
            #[cfg(test)]
            signer: SignerState::Custom(crate::utils::test_signer::test_signer(
                crate::SigningAlg::Ps256,
            )),
            #[cfg(not(test))]
            signer: SignerState::FromSettings(OnceLock::new()),
            _signer_async: None,
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
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_resolver<T: SyncHttpResolver + Send + Sync + 'static>(
        mut self,
        resolver: T,
    ) -> Self {
        self.sync_resolver = SyncResolverState::Custom(Box::new(resolver));
        self
    }

    #[cfg(target_arch = "wasm32")]
    pub fn with_resolver<T: SyncHttpResolver + 'static>(mut self, resolver: T) -> Self {
        self.sync_resolver = SyncResolverState::Custom(Box::new(resolver));
        self
    }

    /// Configure this Context with a custom asynchronous HTTP resolver.
    ///
    /// Async resolvers are used for asynchronous operations like fetching remote manifests.
    ///
    /// # Arguments
    ///
    /// * `resolver` - Any type implementing `AsyncHttpResolver`
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_resolver_async<T: AsyncHttpResolver + Send + Sync + 'static>(
        mut self,
        resolver: T,
    ) -> Self {
        self.async_resolver = AsyncResolverState::Custom(Box::new(resolver));
        self
    }

    #[cfg(target_arch = "wasm32")]
    pub fn with_resolver_async<T: AsyncHttpResolver + 'static>(mut self, resolver: T) -> Self {
        self.async_resolver = AsyncResolverState::Custom(Box::new(resolver));
        self
    }

    /// Returns a reference to the sync resolver.
    ///
    /// The default resolver is a `SyncGenericResolver` wrapped with `RestrictedResolver`
    /// to apply host filtering from the settings.
    pub fn resolver(&self) -> &dyn SyncHttpResolver {
        match &self.sync_resolver {
            SyncResolverState::Custom(resolver) => resolver.as_ref(),
            SyncResolverState::Default(once_lock) => once_lock.get_or_init(|| {
                let inner = SyncGenericResolver::new();
                let mut resolver = RestrictedResolver::new(inner);
                resolver.set_allowed_hosts(self.settings.core.allowed_network_hosts.clone());
                resolver
            }),
        }
    }

    /// Returns a reference to the async resolver.
    ///
    /// The default resolver is an `AsyncGenericResolver` wrapped with `RestrictedResolver`
    /// to apply host filtering from the settings.
    pub fn resolver_async(&self) -> &dyn AsyncHttpResolver {
        match &self.async_resolver {
            AsyncResolverState::Custom(resolver) => resolver.as_ref(),
            AsyncResolverState::Default(once_lock) => once_lock.get_or_init(|| {
                let inner = AsyncGenericResolver::new();
                let mut resolver = RestrictedResolver::new(inner);
                resolver.set_allowed_hosts(self.settings.core.allowed_network_hosts.clone());
                resolver
            }),
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
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_signer<T: Signer + Send + Sync + 'static>(mut self, signer: T) -> Self {
        self.signer = SignerState::Custom(Box::new(signer));
        self
    }

    #[cfg(target_arch = "wasm32")]
    pub fn with_signer<T: Signer + 'static>(mut self, signer: T) -> Self {
        self.signer = SignerState::Custom(Box::new(signer));
        self
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
    /// Returns [`Error::MissingSignerSettings`] if:
    /// - No signer was explicitly set with `with_signer()`
    /// - No signer configuration is present in this Context's settings
    /// - The signer configuration in settings is invalid
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
                    // Create signer from this context's settings
                    if let Some(signer_settings) = &self.settings.signer {
                        let c2pa_signer = signer_settings.clone().c2pa_signer()?;

                        // Check for CAWG x509 wrapper
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
                    Err(_) => Err(Error::MissingSignerSettings), // Treat all errors as missing settings
                }
            }
        }
    }

    // pub fn signer_async(&self) -> Result<&dyn crate::signer::AsyncSigner> {
    //     match self.signer_async.get() {
    //         Some(s) => Ok(s.as_ref()),
    //         None => {
    //             self.signer_async
    //                 .set(Settings::signer_async()?)
    //                 .ok();
    //             Ok(self.signer_async.get().unwrap().as_ref())
    //         }
    //     }
    // }
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
            _signer_async: None,
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
                Err(ref e) => format!("Err({:?})", e),
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
}
