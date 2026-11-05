// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! CMS content envelopes defined by [RFC 5652].
//!
//! [RFC 5652]: https://datatracker.ietf.org/doc/html/rfc5652

use std::io::Write;

use bcder::{
    decode::{Constructed, DecodeError, Source},
    encode::{self, PrimitiveContent, Values},
    Captured, ConstOid, Mode, Oid, Tag,
};

#[cfg(any(test, feature = "sdk-compat"))]
mod signed_data;

#[cfg(test)]
pub(crate) use signed_data::Time;
#[cfg(feature = "sdk-compat")]
pub use signed_data::{SignedData, SignerInfo};

/// Object identifier of the CMS signed-data content type.
///
/// OID: `1.2.840.113549.1.7.2`.
pub const OID_ID_SIGNED_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 2]);

/// CMS content envelope.
///
/// ```ASN.1
/// ContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   content [0] EXPLICIT ANY DEFINED BY contentType }
/// ```
#[derive(Clone, Debug)]
pub struct ContentInfo {
    /// Object identifier selecting the syntax of the encapsulated content.
    pub content_type: ContentType,

    /// `Captured` encoded content, not a verified signature or trust result.
    pub content: Captured,
}

impl PartialEq for ContentInfo {
    fn eq(&self, other: &Self) -> bool {
        self.content_type == other.content_type
            && self.content.as_slice() == other.content.as_slice()
    }
}

impl Eq for ContentInfo {}

impl ContentInfo {
    /// Decode an optional CMS content envelope from its ASN.1 `SEQUENCE`.
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::from_sequence(cons))
    }

    pub(crate) fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let content_type = ContentType::take_from(cons)?;
        let content = cons.take_constructed_if(Tag::CTX_0, |cons| cons.capture_all())?;

        Ok(Self {
            content_type,
            content,
        })
    }
}

impl Values for ContentInfo {
    fn encoded_len(&self, mode: Mode) -> usize {
        encode::sequence((self.content_type.encode_ref(), &self.content)).encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        encode::sequence((self.content_type.encode_ref(), &self.content))
            .write_encoded(mode, target)
    }
}

pub(crate) type ContentType = Oid;
