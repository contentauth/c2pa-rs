use std::cell::OnceCell;

use crate::{
    content_credential::ContentCredential,
    http::{AsyncGenericResolver, AsyncHttpResolver, SyncGenericResolver, SyncHttpResolver},
    settings::Settings,
    AsyncSigner, Result, Signer,
};

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
    pub fn with_settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
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
