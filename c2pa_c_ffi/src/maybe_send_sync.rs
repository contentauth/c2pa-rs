// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License, Version 2.0
// or the MIT license, at your option.

//! Conditional Send/Sync for WASM compatibility.
//! On wasm32 these traits are no-ops so types don't need to implement Send/Sync.

#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

/// Trait alias for `Signer + MaybeSend + MaybeSync` so it can be used in a trait object.
pub trait C2paSignerObject: c2pa::Signer + MaybeSend + MaybeSync {}

impl<T: c2pa::Signer + MaybeSend + MaybeSync> C2paSignerObject for T {}
