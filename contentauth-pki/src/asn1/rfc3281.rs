// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Unsupported attribute-certificate choice from [RFC 3281].
//!
//! [RFC 3281]: https://datatracker.ietf.org/doc/html/rfc3281

use bcder::decode::{Constructed, DecodeError, Source};

/// Uninhabited until attribute-certificate parsing is implemented.
///
/// The legacy CMS decoder explicitly rejects this choice; no partially parsed
/// certificate can be mistaken for supported certificate evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AttributeCertificate {}

impl AttributeCertificate {
    /// Preserve the legacy error after entering the attribute-certificate sequence.
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            Err(cons.content_err("AttributeCertificateInfo parsing not implemented"))
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn attribute_certificates_remain_explicitly_unsupported() {
        let error = bcder::decode::Constructed::decode(
            [0x30, 0].as_slice(),
            bcder::Mode::Der,
            super::AttributeCertificate::take_from,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("AttributeCertificateInfo parsing not implemented"));
    }

    #[test]
    fn malformed_attribute_certificate_envelopes_are_rejected() {
        for bytes in [&[][..], &[0x31, 0], &[0x30, 1]] {
            assert!(bcder::decode::Constructed::decode(
                bytes,
                bcder::Mode::Der,
                super::AttributeCertificate::take_from,
            )
            .is_err());
        }
    }
}
