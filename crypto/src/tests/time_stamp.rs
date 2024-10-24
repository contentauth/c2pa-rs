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

mod cose_timestamp_countersign {
    use ciborium::value::Value;
    use coset::{
        iana::{self, EnumI64},
        HeaderBuilder, ProtectedHeader,
    };

    use crate::{tests::test_utils::temp_signer, time_stamp::cose_timestamp_countersign};

    #[test]
    fn no_tsa_url() {
        let signer = temp_signer();
        let data = b"some sample content to sign";

        let mut protected_h = HeaderBuilder::new().algorithm(iana::Algorithm::PS256);

        let certs = signer.certs().unwrap();

        let sc_der_array_or_bytes = match certs.len() {
            1 => Value::Bytes(certs[0].clone()), // single cert
            _ => {
                let mut sc_der_array: Vec<Value> = Vec::new();
                for cert in certs {
                    sc_der_array.push(Value::Bytes(cert));
                }
                Value::Array(sc_der_array) // provide vec of certs when required
            }
        };

        protected_h = protected_h.value(
            iana::HeaderParameter::X5Chain.to_i64(),
            sc_der_array_or_bytes.clone(),
        );

        let protected_header = protected_h.build();
        let ph2 = ProtectedHeader {
            original_data: None,
            header: protected_header.clone(),
        };

        assert!(cose_timestamp_countersign(signer.as_ref(), data, &ph2).is_none());
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn basic_case_sync() {
        use bcder::decode::Constructed;

        use crate::{
            internal::asn1::rfc3161::{PkiStatus, TimeStampResp},
            openssl::RsaSigner,
            signer::ConfigurableSigner,
            Signer, SigningAlg,
        };

        let sign_cert = include_bytes!("../tests/fixtures/test_certs/ps256.pub").to_vec();
        let pem_key = include_bytes!("../tests/fixtures/test_certs/ps256.pem").to_vec();

        let signer = RsaSigner::from_signcert_and_pkey(
            &sign_cert,
            &pem_key,
            SigningAlg::Ps256,
            Some("http://timestamp.digicert.com".to_owned()),
        )
        .expect("get_temp_signer");

        let signer = Box::new(signer);

        let data = b"some sample content to sign";

        let mut protected_h = HeaderBuilder::new().algorithm(iana::Algorithm::PS256);

        let certs = signer.certs().unwrap();

        let sc_der_array_or_bytes = match certs.len() {
            1 => Value::Bytes(certs[0].clone()), // single cert
            _ => {
                let mut sc_der_array: Vec<Value> = Vec::new();
                for cert in certs {
                    sc_der_array.push(Value::Bytes(cert));
                }
                Value::Array(sc_der_array) // provide vec of certs when required
            }
        };

        protected_h = protected_h.value(
            iana::HeaderParameter::X5Chain.to_i64(),
            sc_der_array_or_bytes.clone(),
        );

        let protected_header = protected_h.build();
        let ph2 = ProtectedHeader {
            original_data: None,
            header: protected_header.clone(),
        };

        let cts = cose_timestamp_countersign(signer.as_ref(), data, &ph2)
            .unwrap()
            .unwrap();

        let tsr = Constructed::decode(&*cts, bcder::Mode::Der, |cons| {
            TimeStampResp::take_from(cons)
        })
        .unwrap();

        let status = tsr.status;
        assert_eq!(status.status, PkiStatus::Granted);
    }
}
