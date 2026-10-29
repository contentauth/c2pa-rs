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

use super::boxes::{
    BMFFBox, CAICBORAssertionBox, CAIJSONAssertionBox, CAISignatureBox, CAIUUIDAssertionBox,
    JUMBFCBORContentBox, JumbfEmbeddedFileBox,
};
use crate::{
    assertion::{Assertion, AssertionData},
    error::Result,
    utils::hash_utils::hash_by_alg,
};

pub(crate) enum AssertionBox {
    Json(CAIJSONAssertionBox),
    Binary(JumbfEmbeddedFileBox),
    Cbor(CAICBORAssertionBox),
    Uuid(CAIUUIDAssertionBox),
}

impl AssertionBox {
    pub(crate) fn into_box(self) -> Box<dyn BMFFBox> {
        match self {
            Self::Json(assertion) => Box::new(assertion),
            Self::Binary(assertion) => Box::new(assertion),
            Self::Cbor(assertion) => Box::new(assertion),
            Self::Uuid(assertion) => Box::new(assertion),
        }
    }

    fn super_box(&self) -> &dyn BMFFBox {
        match self {
            Self::Json(assertion) => assertion.super_box(),
            Self::Binary(assertion) => assertion.super_box(),
            Self::Cbor(assertion) => assertion.super_box(),
            Self::Uuid(assertion) => assertion.super_box(),
        }
    }
}

pub(crate) fn build_assertion_box(
    label: &str,
    assertion: &Assertion,
    salt: Option<Vec<u8>>,
) -> Result<AssertionBox> {
    Ok(match assertion.decode_data() {
        AssertionData::Json(_) => {
            let mut assertion_box = CAIJSONAssertionBox::new(label);
            assertion_box.add_json(assertion.data().to_vec());
            if let Some(salt) = salt {
                assertion_box.set_salt(salt)?;
            }
            AssertionBox::Json(assertion_box)
        }
        AssertionData::Binary(_) => {
            let mut assertion_box = JumbfEmbeddedFileBox::new(label);
            assertion_box.add_data(assertion.data().to_vec(), assertion.mime_type(), None);
            if let Some(salt) = salt {
                assertion_box.set_salt(salt)?;
            }
            AssertionBox::Binary(assertion_box)
        }
        AssertionData::Cbor(_) => {
            let mut assertion_box = CAICBORAssertionBox::new(label);
            assertion_box.add_cbor(assertion.data().to_vec());
            if let Some(salt) = salt {
                assertion_box.set_salt(salt)?;
            }
            AssertionBox::Cbor(assertion_box)
        }
        AssertionData::Uuid(uuid, _) => {
            let mut assertion_box = CAIUUIDAssertionBox::new(label);
            assertion_box.add_uuid(uuid, assertion.data().to_vec())?;
            if let Some(salt) = salt {
                assertion_box.set_salt(salt)?;
            }
            AssertionBox::Uuid(assertion_box)
        }
    })
}

pub(crate) fn build_signature_box(signature: Vec<u8>) -> CAISignatureBox {
    let mut signature_box = CAISignatureBox::new();
    signature_box.add_signature(Box::new(JUMBFCBORContentBox::new(signature)));
    signature_box
}

pub(crate) fn calc_assertion_box_hash(
    label: &str,
    assertion: &Assertion,
    salt: Option<Vec<u8>>,
    alg: &str,
) -> Result<Vec<u8>> {
    let assertion_box = build_assertion_box(label, assertion, salt)?;
    let mut hash_bytes = Vec::with_capacity(2048);
    assertion_box
        .super_box()
        .write_box_payload(&mut hash_bytes)?;
    Ok(hash_by_alg(alg, &hash_bytes, None))
}

pub(crate) fn calc_signature_box_hash(signature: Vec<u8>, alg: &str) -> Result<Vec<u8>> {
    let signature_box = build_signature_box(signature);
    let mut hash_bytes = Vec::with_capacity(2048);
    signature_box
        .super_box()
        .write_box_payload(&mut hash_bytes)?;
    Ok(hash_by_alg(alg, &hash_bytes, None))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn original_assertion_bytes(
        label: &str,
        assertion: &Assertion,
        salt: Option<Vec<u8>>,
    ) -> (Vec<u8>, Vec<u8>) {
        macro_rules! encode {
            ($assertion_box:expr) => {{
                let mut assertion_box = $assertion_box;
                if let Some(salt) = salt {
                    assertion_box.set_salt(salt).unwrap();
                }
                let mut box_bytes = Vec::new();
                assertion_box.write_box(&mut box_bytes).unwrap();
                let mut payload_bytes = Vec::new();
                assertion_box
                    .super_box()
                    .write_box_payload(&mut payload_bytes)
                    .unwrap();
                (box_bytes, payload_bytes)
            }};
        }

        match assertion.decode_data() {
            AssertionData::Json(_) => {
                let mut assertion_box = CAIJSONAssertionBox::new(label);
                assertion_box.add_json(assertion.data().to_vec());
                encode!(assertion_box)
            }
            AssertionData::Binary(_) => {
                let mut assertion_box = JumbfEmbeddedFileBox::new(label);
                assertion_box.add_data(assertion.data().to_vec(), assertion.mime_type(), None);
                encode!(assertion_box)
            }
            AssertionData::Cbor(_) => {
                let mut assertion_box = CAICBORAssertionBox::new(label);
                assertion_box.add_cbor(assertion.data().to_vec());
                encode!(assertion_box)
            }
            AssertionData::Uuid(uuid, _) => {
                let mut assertion_box = CAIUUIDAssertionBox::new(label);
                assertion_box
                    .add_uuid(uuid, assertion.data().to_vec())
                    .unwrap();
                encode!(assertion_box)
            }
        }
    }

    #[test]
    fn assertion_encoding_matches_original_bytes() {
        let assertions = [
            Assertion::from_data_json("test.json", br#"{ "value": 1 }"#).unwrap(),
            Assertion::from_data_binary("test.binary", "image/jpeg", &[0xff, 0xd8, 0xff, 0xd9]),
            Assertion::from_data_cbor("test.cbor", &[0xa1, 0x61, 0x61, 0x01]),
            Assertion::from_data_uuid(
                "test.uuid",
                "12345678123456781234567812345678",
                &[0, 1, 2, 255],
            ),
        ];

        for assertion in &assertions {
            for label in ["test.assertion", "test.assertion__2"] {
                for salt in [None, Some(vec![0x5a; 16])] {
                    let (expected_box, expected_payload) =
                        original_assertion_bytes(label, assertion, salt.clone());
                    let assertion_box =
                        build_assertion_box(label, assertion, salt.clone()).unwrap();
                    let mut payload_bytes = Vec::new();
                    assertion_box
                        .super_box()
                        .write_box_payload(&mut payload_bytes)
                        .unwrap();
                    assert_eq!(payload_bytes, expected_payload);

                    let mut box_bytes = Vec::new();
                    assertion_box.into_box().write_box(&mut box_bytes).unwrap();
                    assert_eq!(box_bytes, expected_box);

                    for alg in ["sha256", "sha384", "sha512"] {
                        assert_eq!(
                            calc_assertion_box_hash(label, assertion, salt.clone(), alg).unwrap(),
                            hash_by_alg(alg, &expected_payload, None)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn signature_encoding_matches_original_bytes() {
        for signature in [Vec::new(), vec![0; 256], vec![0x84, 0x40, 0xa0, 0x40, 0x40]] {
            let mut original_box = CAISignatureBox::new();
            original_box.add_signature(Box::new(JUMBFCBORContentBox::new(signature.clone())));
            let mut expected_box = Vec::new();
            original_box.write_box(&mut expected_box).unwrap();
            let mut expected_payload = Vec::new();
            original_box
                .super_box()
                .write_box_payload(&mut expected_payload)
                .unwrap();

            let mut box_bytes = Vec::new();
            build_signature_box(signature.clone())
                .write_box(&mut box_bytes)
                .unwrap();
            assert_eq!(box_bytes, expected_box);

            for alg in ["sha256", "sha384", "sha512"] {
                assert_eq!(
                    calc_signature_box_hash(signature.clone(), alg).unwrap(),
                    hash_by_alg(alg, &expected_payload, None)
                );
            }
        }
    }
}
