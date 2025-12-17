use std::sync::OnceLock;

use crate::{
    http::{
        restricted::RestrictedResolver, AsyncGenericResolver, AsyncHttpResolver,
        SyncGenericResolver, SyncHttpResolver,
    },
    settings::Settings,
    AsyncSigner, Error, Result, Signer,
};

/// Internal state for sync HTTP resolver selection.
enum SyncResolverState {
    /// User-provided custom resolver.
    Custom(Box<dyn SyncHttpResolver>),
    /// Default resolver with lazy initialization.
    Default(OnceLock<RestrictedResolver<SyncGenericResolver>>),
}

/// Internal state for async HTTP resolver selection.
enum AsyncResolverState {
    /// User-provided custom resolver.
    Custom(Box<dyn AsyncHttpResolver>),
    /// Default resolver with lazy initialization.
    Default(OnceLock<RestrictedResolver<AsyncGenericResolver>>),
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
///    then call [`Settings::signer()`](crate::settings::Settings::signer) to create it:
///
/// ```toml
/// [signer.local]
/// alg = "ps256"
/// sign_cert = "path/to/cert.pem"
/// private_key = "path/to/key.pem"
/// ```
///
/// ```ignore
/// # use c2pa::{Context, settings::Settings, Result};
/// # fn main() -> Result<()> {
/// let context = Context::new()
///     .with_settings(include_str!("config.toml"))?;
///
/// // Create signer from the settings
/// let signer = Settings::signer()?;
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
/// let mut builder = Builder::from_context(context);
///
/// // Get signer from context (created from settings)
/// let signer = builder.context.signer()?;
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
    signer: Option<Box<dyn Signer>>,
    _signer_async: Option<Box<dyn AsyncSigner>>,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            settings: crate::settings::get_settings().unwrap_or_default(),
            sync_resolver: SyncResolverState::Default(OnceLock::new()),
            async_resolver: AsyncResolverState::Default(OnceLock::new()),
            #[cfg(test)]
            signer: Some(crate::utils::test_signer::test_signer(
                crate::SigningAlg::Ps256,
            )),
            #[cfg(not(test))]
            signer: None,
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
    pub fn with_signer<T: Signer + 'static>(mut self, signer: T) -> Self {
        self.signer = Some(Box::new(signer));
        self
    }

    /// Returns a reference to the signer configured with [`with_signer()`](Context::with_signer).
    ///
    /// **Note:** This method returns the signer that was explicitly set using `with_signer()`.
    /// If you want to create a signer from settings, use [`Settings::signer()`](crate::settings::Settings::signer) instead.
    ///
    /// # Returns
    ///
    /// A reference to the configured signer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingSignerSettings`] if no signer was set with `with_signer()`.
    ///
    /// # Examples
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
        self.signer
            .as_ref()
            .ok_or_else(|| crate::Error::MissingSignerSettings)
            .map(|s| s.as_ref())
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
}
