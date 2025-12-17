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

/// A trait for types that can be converted into Settings
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
    pub fn new() -> Self {
        Self::default()
    }

    /// use the provided settings in this context
    pub fn with_settings<S: IntoSettings>(mut self, settings: S) -> Result<Self> {
        self.settings = settings.into_settings()?;
        Ok(self)
    }

    /// Returns a reference to the settings.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Returns a mutable reference to the settings.
    pub fn settings_mut(&mut self) -> &mut Settings {
        &mut self.settings
    }

    /// Use the provided sync resolver in this context
    pub fn with_resolver<T: SyncHttpResolver + 'static>(mut self, resolver: T) -> Self {
        self.sync_resolver = SyncResolverState::Custom(Box::new(resolver));
        self
    }

    /// Use the provided async resolver in this context
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

    /// Use the provided signer in this context
    pub fn with_signer<T: Signer + 'static>(mut self, signer: T) -> Self {
        self.signer = Some(Box::new(signer));
        self
    }

    /// Returns a reference to the signer.
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
