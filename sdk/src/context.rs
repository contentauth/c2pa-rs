
use std::cell::OnceCell;
use crate::{
    content_credential::ContentCredential,
    settings::Settings,
    http::{SyncGenericResolver, AsyncGenericResolver, SyncHttpResolver, AsyncHttpResolver},
};

pub enum HttpResolver {
    Sync(Box<dyn SyncHttpResolver>),
    Async(Box<dyn AsyncHttpResolver>),
}

pub struct Context {
    settings: Settings, 
    http_resolver: OnceCell<Box<dyn SyncHttpResolver>>,
    http_resolver_async: OnceCell<Box<dyn AsyncHttpResolver>>,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            settings: Settings::default(),
            http_resolver: OnceCell::new(),
            http_resolver_async: OnceCell::new(),
        }
    }
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    pub fn with_resolver<T: SyncHttpResolver + 'static>(
        self,
        resolver: T,
    ) -> Self {
        let _ = self.http_resolver.set(Box::new(resolver));
        self
    }

    pub fn with_resolver_async<T: AsyncHttpResolver + 'static>(
        self,
        resolver: T,
    ) -> Self {
        let _ = self.http_resolver_async.set(Box::new(resolver));
        self
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn settings_mut(&mut self) -> &mut Settings {
        &mut self.settings
    }

    pub fn resolver(&self) ->&dyn SyncHttpResolver {
        self.http_resolver
            .get_or_init(|| Box::new(SyncGenericResolver::new()))
            .as_ref()
    }

    pub fn resolver_async(&self) -> &dyn AsyncHttpResolver {
        self.http_resolver_async
            .get_or_init(|| Box::new(AsyncGenericResolver::new()))
            .as_ref()
    }

    pub fn content_credential(&self) -> ContentCredential {
        ContentCredential::new(&self)
    }

}
