// Copyright 2025 Adobe. All rights reserved.
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

//! The `maybe_send_sync` module provides a trait that conditionally requires `Send`
//! based on the target architecture. This is necessary because WASM32 targets
//! do not support the `Send` trait for async operations.
//!
//! This pattern is inspired by Apache OpenDAL's approach to handling WASM compatibility.
//!
//! # Why only MaybeSend?
//!
//! WASM is single-threaded, so the `Send` trait (which indicates a type can be transferred
//! across threads) doesn't apply. The `async_trait` macro requires `Send` bounds on futures
//! for multi-threaded contexts, which is why we need `#[async_trait(?Send)]` for WASM.
/// A trait that is `Send` on non-WASM targets and not `Send` on WASM targets.
///
/// This is useful for traits and generic bounds that need to conditionally require `Send`
/// based on whether the code is targeting WASM or native platforms.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::maybe_send_sync::MaybeSend;
///
/// // Use in trait bounds
/// pub fn process<T: MaybeSend>(value: T) -> Result<()> {
///     // On native: T must be Send
///     // On WASM: T can be anything
/// }
///
/// // Use in trait definitions (though typically you'd use #[cfg_attr] with async_trait)
/// pub trait MyTrait: MaybeSend {
///     fn my_method(&self);
/// }
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// A trait that is `Sync` on non-WASM targets and not `Sync` on WASM targets.
///
/// This is useful for traits and generic bounds that need to conditionally require `Sync`
/// based on whether the code is targeting WASM or native platforms.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::maybe_send_sync::MaybeSync;
///
/// // Use in trait bounds
/// pub fn process<T: MaybeSync>(value: T) -> Result<()> {
///     // On native: T must be Sync
///     // On WASM: T can be anything
/// }
///
/// // Use in trait definitions
/// pub trait MyTrait: MaybeSync {
///     fn my_method(&self);
/// }
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}
