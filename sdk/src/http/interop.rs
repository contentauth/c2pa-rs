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

//! Type aliases and traits for boxed and arced HTTP resolvers with conditional Send + Sync bounds.
//! These are particularly useful when dealing with trait objects, such as in the case of [`Context`].
//!
//! [`Context`]: crate::Context

use std::{io::Read, sync::Arc};

use async_trait::async_trait;
use http::{Request, Response};

use crate::http::{AsyncHttpResolver, HttpResolverError, SyncHttpResolver};

/// Type alias for a boxed [`SyncHttpResolver`] with conditional Send + Sync bounds.
/// On non-WASM targets, the resolver is Send + Sync for thread-safe usage.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedSyncResolver = Box<dyn SyncHttpResolver + Send + Sync>;

/// Type alias for a boxed [`SyncHttpResolver`] without Send + Sync bounds (WASM only).
#[cfg(target_arch = "wasm32")]
pub type BoxedSyncResolver = Box<dyn SyncHttpResolver>;

#[cfg(not(target_arch = "wasm32"))]
pub type AsyncResolver = dyn AsyncHttpResolver + Send + Sync;

#[cfg(target_arch = "wasm32")]
pub type AsyncResolver = dyn AsyncHttpResolver;

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<T: AsyncHttpResolver + Send + Sync + ?Sized> AsyncHttpResolver for Arc<T> {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        (**self).http_resolve_async(request).await
    }
}
