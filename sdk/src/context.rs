use crate::{
    http::{AsyncGenericResolver, AsyncHttpResolver, SyncGenericResolver, SyncHttpResolver},
    settings::Settings,
    AsyncSigner, Error, Result, Signer,
};

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
    http_resolver: Option<Box<dyn SyncHttpResolver>>,
    http_resolver_async: Option<Box<dyn AsyncHttpResolver>>,
    signer: Option<Box<dyn Signer>>,
    _signer_async: Option<Box<dyn AsyncSigner>>,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            settings: crate::settings::get_settings().unwrap_or_default(),
            http_resolver: None,
            http_resolver_async: None,
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
        self.http_resolver = Some(Box::new(resolver));
        self
    }

    /// Use the provided async resolver in this context
    pub fn with_resolver_async<T: AsyncHttpResolver + 'static>(mut self, resolver: T) -> Self {
        self.http_resolver_async = Some(Box::new(resolver));
        self
    }

    /// Returns a reference to the sync resolver.
    pub fn resolver(&self) -> &dyn SyncHttpResolver {
        use std::sync::OnceLock;
        static DEFAULT: OnceLock<SyncGenericResolver> = OnceLock::new();
        self.http_resolver
            .as_ref()
            .map(|r| r.as_ref())
            .unwrap_or(DEFAULT.get_or_init(SyncGenericResolver::new))
    }

    /// Returns a reference to the async resolver.
    pub fn resolver_async(&self) -> &dyn AsyncHttpResolver {
        use std::sync::OnceLock;
        static DEFAULT: OnceLock<AsyncGenericResolver> = OnceLock::new();
        self.http_resolver_async
            .as_ref()
            .map(|r| r.as_ref())
            .unwrap_or(DEFAULT.get_or_init(AsyncGenericResolver::new))
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
