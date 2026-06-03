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

//! A minimal ASN.1 object identifier type used at this crate's public API
//! boundary so that callers need not depend on a particular ASN.1 crate.

/// An ASN.1 object identifier, represented by its DER _content octets_ (the
/// encoded sub-identifiers, without the leading tag and length).
///
/// Most ASN.1 crates expose an OID's content octets directly: for example,
/// `bcder::Oid` and `x509_parser`/`asn1_rs` OIDs both yield them via
/// `as_ref()` / `as_bytes()`. Construct an [`Oid`] from those bytes with
/// [`Oid::new`] (or `Oid::from`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Oid<'a> {
    content_octets: &'a [u8],
}

impl<'a> Oid<'a> {
    /// Creates an [`Oid`] from its DER content octets.
    pub const fn new(content_octets: &'a [u8]) -> Self {
        Self { content_octets }
    }

    /// Returns the DER content octets of this OID.
    pub fn as_bytes(&self) -> &[u8] {
        self.content_octets
    }
}

impl<'a> From<&'a [u8]> for Oid<'a> {
    fn from(content_octets: &'a [u8]) -> Self {
        Self::new(content_octets)
    }
}
