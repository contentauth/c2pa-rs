// Copyright 2024 Adobe. All rights reserved.
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

//! The `maybe_send` module provides a trait that conditionally requires `Send`
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
//!
//! The `Sync` trait is not problematic in WASM - it's simply omitted from WASM trait
//! definitions because it's meaningless in a single-threaded context, not because it causes
//! issues. Therefore, we only need `MaybeSend`, not `MaybeSync`.

/// A trait that is `Send` on non-WASM targets and not `Send` on WASM targets.
///
/// This is useful for traits and generic bounds that need to conditionally require `Send`
/// based on whether the code is targeting WASM or native platforms.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::maybe_send::MaybeSend;
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

/// A trait that is not `Send` on WASM targets.
///
/// This is useful for traits and generic bounds that need to conditionally require `Send`
/// based on whether the code is targeting WASM or native platforms.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}

#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

#[cfg(test)]
mod tests {
    use super::*;

    // Test that MaybeSend works with common types
    #[test]
    fn test_maybe_send_with_standard_types() {
        fn assert_maybe_send<T: MaybeSend>() {}

        // These should all implement MaybeSend
        assert_maybe_send::<String>();
        assert_maybe_send::<Vec<u8>>();
        assert_maybe_send::<i32>();
    }

    // Example trait using MaybeSend
    trait ExampleTrait: MaybeSend {
        fn process(&self) -> String;
    }

    struct ExampleType;

    impl ExampleType {
        fn _new() -> Self {
            Self
        }
    }

    impl ExampleTrait for ExampleType {
        fn process(&self) -> String {
            "processed".to_string()
        }
    }

    #[test]
    fn test_trait_with_maybe_send() {
        let example = ExampleType;
        assert_eq!(example.process(), "processed");
    }

    // Test that we can use MaybeSend in generic contexts
    #[test]
    fn test_generic_function_with_maybe_send() {
        fn takes_maybe_send<T: MaybeSend>(_value: T) {
            // This compiles because T: MaybeSend
        }

        takes_maybe_send(String::from("test"));
        takes_maybe_send(vec![1, 2, 3]);
    }
}
