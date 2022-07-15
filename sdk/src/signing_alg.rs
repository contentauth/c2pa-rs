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

#![deny(missing_docs)]

use std::{fmt, str::FromStr};

/// Describes the digital signature algorithms allowed by the C2PA spec.
///
/// Per <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_digital_signatures>:
///
/// > All digital signatures that are stored in a C2PA Manifest shall
/// > be generated using one of the digital signature algorithms and
/// > key types listed as described in this section.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SigningAlg {
    /// ECDSA with SHA-256
    Es256,

    /// ECDSA with SHA-384
    Es384,

    /// ECDSA with SHA-512
    Es512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    Ps256,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    Ps384,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    Ps512,

    /// Edwards-Curve DSA (Ed25519 instance only)
    Ed25519,
}

impl FromStr for SigningAlg {
    type Err = UnknownAlgorithmError;

    fn from_str(alg: &str) -> Result<Self, Self::Err> {
        match alg {
            "es256" => Ok(Self::Es256),
            "es384" => Ok(Self::Es384),
            "es512" => Ok(Self::Es512),
            "ps256" => Ok(Self::Ps256),
            "ps384" => Ok(Self::Ps384),
            "ps512" => Ok(Self::Ps512),
            "ed25519" => Ok(Self::Ed25519),
            _ => Err(UnknownAlgorithmError(alg.to_owned())),
        }
    }
}

impl fmt::Display for SigningAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                Self::Es256 => "es256",
                Self::Es384 => "es384",
                Self::Es512 => "es512",
                Self::Ps256 => "ps256",
                Self::Ps384 => "ps384",
                Self::Ps512 => "ps512",
                Self::Ed25519 => "ed25519",
            }
        )
    }
}

#[derive(Debug, PartialEq)]
/// This error is thrown when converting from a string to [`SigningAlg`]
/// if the algorithm string is unrecognized.
///
/// The string must be one of "es256", "es384", "es512", "ps256", "ps384",
/// "ps512", or "ed25519".
pub struct UnknownAlgorithmError(String);

impl fmt::Display for UnknownAlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "UnknownAlgorithmError({})", self.0)
    }
}

impl std::error::Error for UnknownAlgorithmError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn alg_from_str() {
        assert_eq!("es256".parse(), Ok(SigningAlg::Es256));
        assert_eq!("es384".parse(), Ok(SigningAlg::Es384));
        assert_eq!("es512".parse(), Ok(SigningAlg::Es512));
        assert_eq!("ps256".parse(), Ok(SigningAlg::Ps256));
        assert_eq!("ps384".parse(), Ok(SigningAlg::Ps384));
        assert_eq!("ps512".parse(), Ok(SigningAlg::Ps512));
        assert_eq!("ed25519".parse(), Ok(SigningAlg::Ed25519));

        let r: Result<SigningAlg, UnknownAlgorithmError> = "bogus".parse();
        assert_eq!(r, Err(UnknownAlgorithmError("bogus".to_string())));
    }

    #[test]
    fn signing_alg_impl_display() {
        assert_eq!(format!("{}", SigningAlg::Es256), "es256");
        assert_eq!(format!("{}", SigningAlg::Es384), "es384");
        assert_eq!(format!("{}", SigningAlg::Es512), "es512");
        assert_eq!(format!("{}", SigningAlg::Ps256), "ps256");
        assert_eq!(format!("{}", SigningAlg::Ps384), "ps384");
        assert_eq!(format!("{}", SigningAlg::Ps512), "ps512");
        assert_eq!(format!("{}", SigningAlg::Ed25519), "ed25519");
    }

    #[test]
    fn err_impl_display() {
        assert_eq!(
            format!("{}", UnknownAlgorithmError("bogus".to_owned())),
            "UnknownAlgorithmError(bogus)"
        );
    }
}
