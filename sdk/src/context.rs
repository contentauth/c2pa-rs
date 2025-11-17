use std::cell::OnceCell;

use crate::{
    content_credential::ContentCredential,
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
    http_resolver: OnceCell<Box<dyn SyncHttpResolver>>,
    http_resolver_async: OnceCell<Box<dyn AsyncHttpResolver>>,
    signer: OnceCell<Box<dyn Signer>>,
    _signer_async: OnceCell<Box<dyn AsyncSigner>>,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            settings: crate::settings::get_settings().unwrap_or_default(),
            http_resolver: OnceCell::new(),
            http_resolver_async: OnceCell::new(),
            signer: OnceCell::new(),
            _signer_async: OnceCell::new(),
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
    pub fn with_resolver<T: SyncHttpResolver + 'static>(self, resolver: T) -> Self {
        let _ = self.http_resolver.set(Box::new(resolver));
        self
    }

    /// Use the provided async resolver in this context
    pub fn with_resolver_async<T: AsyncHttpResolver + 'static>(self, resolver: T) -> Self {
        let _ = self.http_resolver_async.set(Box::new(resolver));
        self
    }

    /// Returns a reference to the sync resolver.
    pub fn resolver(&self) -> &dyn SyncHttpResolver {
        self.http_resolver
            .get_or_init(|| Box::new(SyncGenericResolver::new()))
            .as_ref()
    }

    /// Returns a reference to the async resolver.
    pub fn resolver_async(&self) -> &dyn AsyncHttpResolver {
        self.http_resolver_async
            .get_or_init(|| Box::new(AsyncGenericResolver::new()))
            .as_ref()
    }

    /// Returns a reference to the signer.
    #[allow(clippy::unwrap_used)] // switch to get_or_try_init when stable
    pub fn signer(&self) -> Result<&dyn Signer> {
        match self.signer.get() {
            Some(s) => Ok(s),
            None => {
                if let Some(c2pa_settings) = self.settings().signer.clone() {
                    let mut signer = c2pa_settings.c2pa_signer()?;
                    if let Some(cawg_settings) = self.settings().cawg_x509_signer.clone() {
                        signer = cawg_settings.cawg_signer(signer)?;
                    }
                    self.signer.set(signer).ok();
                    return Ok(self.signer.get().unwrap());
                }
                #[cfg(test)]
                {
                    self.signer
                        .set(crate::utils::test_signer::test_signer(
                            crate::SigningAlg::Ps256,
                        ))
                        .ok();
                    Ok(self.signer.get().unwrap())
                }
                #[cfg(not(test))]
                {
                    Err(crate::Error::MissingSignerSettings)
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

    pub fn content_credential(&self) -> ContentCredential<'_> {
        ContentCredential::new(self)
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
}
