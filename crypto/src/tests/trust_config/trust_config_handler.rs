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

mod trait_trust_handler_config {
    use std::{collections::HashSet, io::Read};

    use asn1_rs::Oid;

    use crate::{Result, TrustHandlerConfig};

    pub struct BoringTrustHandler {}

    impl TrustHandlerConfig for BoringTrustHandler {
        fn new() -> Self {
            unimplemented!();
        }

        fn load_trust_anchors_from_data(&mut self, _trust_data: &mut dyn Read) -> Result<()> {
            unimplemented!();
        }

        fn load_allowed_list(&mut self, _allowed_list: &mut dyn Read) -> Result<()> {
            unimplemented!();
        }

        fn append_private_trust_data(
            &mut self,
            _private_anchors_data: &mut dyn Read,
        ) -> Result<()> {
            unimplemented!();
        }

        fn clear(&mut self) {
            unimplemented!();
        }

        fn load_configuration(&mut self, _config_data: &mut dyn Read) -> Result<()> {
            unimplemented!();
        }

        fn get_auxiliary_ekus(&self) -> Vec<Oid> {
            unimplemented!();
        }

        fn get_anchors(&self) -> Vec<Vec<u8>> {
            unimplemented!();
        }

        fn get_allowed_list(&self) -> &HashSet<String> {
            unimplemented!();
        }
    }

    #[test]
    fn impl_debug() {
        let bth: Box<dyn TrustHandlerConfig> = Box::new(BoringTrustHandler {});
        assert_eq!(format!("{bth:?}"), "TrustHandler Installed");
    }
}

mod has_allowed_oid {
    use asn1_rs::{oid, FromDer, Oid, ToDer};

    use crate::trust_config::trust_handler_config::*;

    #[test]
    fn email_protection() {
        let oid_vec = vec![EMAIL_PROTECTION_OID.clone()];
        let oid_der = oid_vec.to_der_vec().unwrap();
        let (_, eku) = x509_parser::extensions::ExtendedKeyUsage::from_der(&oid_der).unwrap();

        let additional_ekus: Vec<Oid> = vec![];

        assert_eq!(
            has_allowed_oid(&eku, &additional_ekus),
            Some(&EMAIL_PROTECTION_OID)
        );
    }

    #[test]
    fn time_stamping() {
        let oid_vec = vec![TIMESTAMPING_OID.clone()];
        let oid_der = oid_vec.to_der_vec().unwrap();
        let (_, eku) = x509_parser::extensions::ExtendedKeyUsage::from_der(&oid_der).unwrap();

        let additional_ekus: Vec<Oid> = vec![];

        assert_eq!(
            has_allowed_oid(&eku, &additional_ekus),
            Some(&TIMESTAMPING_OID)
        );
    }

    #[test]
    fn ocsp_signing() {
        let oid_vec = vec![OCSP_SIGNING_OID.clone()];
        let oid_der = oid_vec.to_der_vec().unwrap();
        let (_, eku) = x509_parser::extensions::ExtendedKeyUsage::from_der(&oid_der).unwrap();

        let additional_ekus: Vec<Oid> = vec![];

        assert_eq!(
            has_allowed_oid(&eku, &additional_ekus),
            Some(&OCSP_SIGNING_OID)
        );
    }

    pub(crate) static BOGUS_OID: Oid<'static> = oid!(1.2.3 .4);
    pub(crate) static BOGUS_OID_2: Oid<'static> = oid!(1.2.3 .5);

    #[test]
    fn other_oid() {
        let oid_vec = vec![BOGUS_OID.clone()];
        let oid_der = oid_vec.to_der_vec().unwrap();
        let (_, eku) = x509_parser::extensions::ExtendedKeyUsage::from_der(&oid_der).unwrap();

        let additional_ekus: Vec<Oid> = vec![];

        assert!(has_allowed_oid(&eku, &additional_ekus).is_none());
    }

    #[test]
    fn other_oid_allow_listed() {
        let oid_vec = vec![BOGUS_OID.clone()];
        let oid_der = oid_vec.to_der_vec().unwrap();
        let (_, eku) = x509_parser::extensions::ExtendedKeyUsage::from_der(&oid_der).unwrap();

        let additional_ekus: Vec<Oid> = vec![BOGUS_OID.clone()];

        assert_eq!(has_allowed_oid(&eku, &additional_ekus), Some(&BOGUS_OID));
    }

    #[test]
    fn other_oid_not_on_allow_list() {
        let oid_vec = vec![BOGUS_OID_2.clone()];
        let oid_der = oid_vec.to_der_vec().unwrap();
        let (_, eku) = x509_parser::extensions::ExtendedKeyUsage::from_der(&oid_der).unwrap();

        let additional_ekus: Vec<Oid> = vec![BOGUS_OID.clone()];

        assert!(has_allowed_oid(&eku, &additional_ekus).is_none());
    }
}

mod load_eku_configuration {
    use std::io::Cursor;

    use crate::trust_config::trust_handler_config::load_eku_configuration;

    #[test]
    fn openssl_store_cfg() {
        let oids = include_bytes!("../../openssl/store.cfg");
        let mut cursor = Cursor::new(oids);

        let ekus = load_eku_configuration(&mut cursor).unwrap();

        let mut eku_iter = ekus.iter();

        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.4");
        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.36");

        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.8");
        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.9");
        assert_eq!(
            eku_iter.next().unwrap().as_str(),
            "1.3.6.1.4.1.311.76.59.1.9"
        );
        assert!(eku_iter.next().is_none());
    }

    #[test]
    fn skips_non_oids() {
        let oids = "1.3.6.1.5.5.7.3.4\nbogus\n1.3.6.1.5.5.7.3.36";
        let mut cursor = Cursor::new(oids);

        let ekus = load_eku_configuration(&mut cursor).unwrap();

        let mut eku_iter = ekus.iter();
        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.4");
        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.36");
        assert!(eku_iter.next().is_none());
    }
}

#[cfg(feature = "openssl")] // TEMPORARY until temp_signer is generic
mod load_trust_from_data {
    use crate::{
        tests::openssl::temp_signer, trust_config::trust_handler_config::load_trust_from_data,
        Error, Signer, SigningAlg,
    };

    #[test]
    fn allowed_list_pem() {
        let allowed_list = include_bytes!("../fixtures/allow_list/allowed_list.pem").to_vec();
        let allowed_list = load_trust_from_data(&allowed_list).unwrap();

        let not_a_cert = b"bogus".to_vec();
        assert!(!allowed_list.contains(&not_a_cert));

        let ps256 = temp_signer::get_rsa_signer(SigningAlg::Ps256, None);
        let ps256_certs = ps256.certs().unwrap();
        assert!(allowed_list.contains(&ps256_certs[0].to_owned()));

        let ps384 = temp_signer::get_rsa_signer(SigningAlg::Ps384, None);
        let ps384_certs = ps384.certs().unwrap();
        assert!(allowed_list.contains(&ps384_certs[0].to_owned()));

        let ps512 = temp_signer::get_rsa_signer(SigningAlg::Ps512, None);
        let ps512_certs = ps512.certs().unwrap();
        assert!(allowed_list.contains(&ps512_certs[0].to_owned()));
    }

    #[test]
    fn errors_on_invalid_pem() {
        let allowed_list =
            b"-----BEGIN CERTIFICATE-----\nnot a valid certificate\n-----END CERTIFICATE-----\n"
                .to_vec();
        let err = load_trust_from_data(&allowed_list).unwrap_err();
        match err {
            Error::CoseInvalidCert => (),
            _ => {
                panic!("Unexpected error: {err:#?}");
            }
        }
    }
}
