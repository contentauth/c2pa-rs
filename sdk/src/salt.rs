// Copyright 2022 Adobe. All rights reserved.
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

/// The SaltGenerator trait always the caller to supply
/// a function to generate a salt value used when hashing
/// data.  Providing a unique salt ensures a unique hash for
/// a given data set.

pub trait SaltGenerator {
    /// generate a salt vector
    fn generate_salt(&self) -> Option<Vec<u8>>;
}

/// NoSalt return a no salt option to a function
pub struct NoSalt {}

impl SaltGenerator for NoSalt {
    fn generate_salt(&self) -> Option<Vec<u8>> {
        None
    }
}

/// const NoSalt instance that can be used when no salting is required
pub const NO_SALT: &NoSalt = &NoSalt {};

/// Default salt generator
/// This generator uses OpenSSL to generate a
/// salt of the specified length (default 16 bytes)
pub struct DefaultSalt {
    salt_len: usize,
}

impl DefaultSalt {
    /// Set the length of the generated salt vector
    #[allow(dead_code)]
    pub fn set_salt_length(&mut self, len: usize) {
        self.salt_len = len;
    }
}

impl Default for DefaultSalt {
    fn default() -> Self {
        DefaultSalt { salt_len: 16 }
    }
}

impl SaltGenerator for DefaultSalt {
    fn generate_salt(&self) -> Option<Vec<u8>> {
        #[cfg(all(feature = "openssl_sign", not(target_os = "wasi")))]
        {
            let mut salt = vec![0u8; self.salt_len];
            openssl::rand::rand_bytes(&mut salt).ok()?;

            Some(salt)
        }
        #[cfg(all(
            not(feature = "openssl_sign"),
            target_arch = "wasm32",
            not(target_os = "wasi")
        ))]
        {
            let salt = crate::wasm::util::get_random_values(self.salt_len).ok()?;

            Some(salt)
        }
        #[cfg(any(
            target_os = "wasi",
            all(not(feature = "openssl_sign"), not(target_arch = "wasm32"))
        ))]
        {
            use rand::prelude::*;

            let mut salt = vec![0u8; self.salt_len];
            let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
            rng.fill_bytes(&mut salt);

            Some(salt)
        }
    }
}
