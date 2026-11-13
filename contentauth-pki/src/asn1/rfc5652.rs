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
        encode::sequence((
            self.content_type.encode_ref(),
            (&self.content).explicit(Tag::CTX_0),
        ))
        .encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        encode::sequence((
            self.content_type.encode_ref(),
            (&self.content).explicit(Tag::CTX_0),
        ))
        .write_encoded(mode, target)
    }
}

pub(crate) type ContentType = Oid;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn envelope(oid: &[u8], value: u8) -> ContentInfo {
        ContentInfo {
            content_type: Oid(bytes::Bytes::copy_from_slice(oid)),
            content: Captured::from_values(Mode::Der, value.encode()),
        }
    }

    #[test]
    fn content_envelopes_roundtrip_without_changing_captured_content() {
        for size in [0, 127, 128, 256] {
            let original = ContentInfo {
                content_type: Oid(bytes::Bytes::from_static(&[0x2a, 3, 4])),
                content: Captured::from_values(
                    Mode::Der,
                    bcder::OctetString::encode_slice(&vec![0xab; size]),
                ),
            };
            let mut encoded = Vec::new();
            original.write_encoded(Mode::Der, &mut encoded).unwrap();
            assert_eq!(encoded.len(), original.encoded_len(Mode::Der));
            let decoded =
                Constructed::decode(encoded.as_slice(), Mode::Der, ContentInfo::take_opt_from)
                    .unwrap()
                    .unwrap();
            assert_eq!(decoded, original);
            assert_eq!(decoded.content.as_slice(), original.content.as_slice());
        }
    }

    #[test]
    fn content_encoding_includes_the_explicit_context_wrapper() {
        let content = envelope(&[0x2a, 3, 4], 0);
        let mut encoded = Vec::new();
        content.write_encoded(Mode::Der, &mut encoded).unwrap();
        assert_eq!(encoded, [0x30, 0x0a, 6, 3, 0x2a, 3, 4, 0xa0, 3, 2, 1, 0]);
    }

    #[test]
    fn envelope_equality_compares_both_oid_and_encoded_content() {
        assert_eq!(envelope(&[0x2a, 3, 4], 1), envelope(&[0x2a, 3, 4], 1));
        assert_ne!(envelope(&[0x2a, 3, 4], 1), envelope(&[0x2a, 3, 5], 1));
        assert_ne!(envelope(&[0x2a, 3, 4], 1), envelope(&[0x2a, 3, 4], 2));
    }

    #[test]
    fn missing_and_malformed_envelopes_do_not_decode_as_content() {
        assert!(
            Constructed::decode(&[][..], Mode::Der, ContentInfo::take_opt_from)
                .unwrap()
                .is_none()
        );

        for bytes in [
            &[0x30, 0][..],
            &[0x30, 5, 6, 3, 0x2a, 3, 4],
            &[0x30, 7, 6, 3, 0x2a, 3, 4, 0xa1, 0],
        ] {
            assert!(Constructed::decode(bytes, Mode::Der, ContentInfo::take_opt_from).is_err());
        }
    }

    #[test]
    fn envelope_encoding_propagates_writer_failures() {
        struct BrokenWriter;

        impl std::io::Write for BrokenWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("test writer failure"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        assert_eq!(
            envelope(&[0x2a, 3, 4], 1)
                .write_encoded(Mode::Der, &mut BrokenWriter)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Other
        );
    }
}
