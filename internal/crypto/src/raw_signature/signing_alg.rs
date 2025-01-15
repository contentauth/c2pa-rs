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

use std::{fmt, str::FromStr};

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Describes the digital signature algorithms allowed by the C2PA spec.
///
/// Per [§13.2, “Digital Signatures”]:
///
/// > All digital signatures applied as per the technical requirements of this
/// > specification shall be generated using one of the digital signature
/// > algorithms and key types listed as described in this section.
///
/// [§13.2, “Digital Signatures”]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_digital_signatures
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[non_exhaustive]
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

#[derive(Debug, PartialEq, Eq)]
/// This error is thrown when converting from a string to [`SigningAlg`]
/// if the algorithm string is unrecognized.
///
/// The string must be one of "es256", "es384", "es512", "ps256", "ps384",
/// "ps512", or "ed25519".
pub struct UnknownAlgorithmError(pub String);

impl fmt::Display for UnknownAlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "UnknownAlgorithmError({})", self.0)
    }
}

impl std::error::Error for UnknownAlgorithmError {}
