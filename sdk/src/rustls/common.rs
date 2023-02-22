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

use std::{io::BufReader, iter};

use rustls::Certificate;
use rustls_pemfile::{read_one, Item};
use x509_parser::{
    der_parser::{
        self,
        der::{parse_der_integer, parse_der_sequence_defined_g},
    },
    parse_x509_certificate,
    traits::FromDer,
    x509::AlgorithmIdentifier,
};

use crate::{
    cose_validator::{
        ECDSA_WITH_SHA256_OID, ECDSA_WITH_SHA384_OID, ED25519_OID, RSASSA_PSS_OID, SHA256_OID,
        SHA384_OID, SHA512_OID,
    },
    Error, Result, SigningAlg,
};

pub(crate) struct AlgorithmData {
    pub rustls_id: rustls::SignatureScheme,
    pub verification_alg: &'static dyn ring::signature::VerificationAlgorithm,
}

pub(crate) fn get_algorithm_data(alg: &SigningAlg) -> Result<AlgorithmData> {
    match alg {
        // RSASSA-PSS
        SigningAlg::Ps256 => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::RSA_PSS_SHA256,
            verification_alg: &ring::signature::RSA_PSS_2048_8192_SHA256,
        }),
        SigningAlg::Ps384 => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::RSA_PSS_SHA384,
            verification_alg: &ring::signature::RSA_PSS_2048_8192_SHA384,
        }),
        SigningAlg::Ps512 => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::RSA_PSS_SHA512,
            verification_alg: &ring::signature::RSA_PSS_2048_8192_SHA512,
        }),
        // ECDSA
        SigningAlg::Es256 => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            verification_alg: &ring::signature::ECDSA_P256_SHA256_ASN1,
        }),
        SigningAlg::Es384 => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            verification_alg: &ring::signature::ECDSA_P384_SHA384_ASN1,
        }),
        // Ed25519
        SigningAlg::Ed25519 => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::ED25519,
            verification_alg: &ring::signature::ED25519,
        }),
        _ => Err(Error::RustlsUnknownAlgorithmError),
    }
}

pub fn certificate_to_alg(certificate_u8: &[u8]) -> Result<SigningAlg> {
    let certificate = match parse_x509_certificate(certificate_u8) {
        Ok((_rem, certificate)) => certificate,
        Err(_) => {
            return Err(Error::CoseSignature);
        }
    };

    let algorithm = certificate.signature_algorithm.algorithm.clone();

    if algorithm == ECDSA_WITH_SHA256_OID {
        return Ok(SigningAlg::Es256);
    } else if algorithm == ECDSA_WITH_SHA384_OID {
        return Ok(SigningAlg::Es384);
    } else if algorithm == ED25519_OID {
        return Ok(SigningAlg::Ed25519);
    };

    if algorithm != RSASSA_PSS_OID {
        return Err(Error::CoseSignature);
    }

    if let Some(parameters) = certificate.signature_algorithm.parameters {
        let sequence = parameters
            .as_sequence()
            .map_err(|_err| Error::CoseInvalidCert)?;

        let (_b, alg) = match AlgorithmIdentifier::from_der(
            sequence[0]
                .content
                .as_slice()
                .map_err(|_err| Error::CoseInvalidCert)?,
        ) {
            Ok(alg_id) => alg_id,
            Err(_) => {
                return Err(Error::CoseSignature);
            }
        };

        let alg_oid = alg.algorithm;
        if alg_oid == SHA256_OID {
            Ok(SigningAlg::Ps256)
        } else if alg_oid == SHA384_OID {
            Ok(SigningAlg::Ps384)
        } else if alg_oid == SHA512_OID {
            Ok(SigningAlg::Ps512)
        } else {
            Err(Error::CoseSignature)
        }
    } else {
        Err(Error::CoseSignature)
    }
}

pub(crate) fn ensure_asn_sig(data: &[u8], alg: SigningAlg) -> Result<Vec<u8>> {
    match alg {
        SigningAlg::Es256 => {
            if data.len() != 64 {
                return Err(Error::CoseSignature);
            }

            let mut r = p256::FieldBytes::default();
            let mut s = p256::FieldBytes::default();
            let sig_len = data.len() / 2;

            r.copy_from_slice(&data[0..sig_len]);
            s.copy_from_slice(&data[sig_len..]);

            let sig_asn =
                p256::ecdsa::Signature::from_scalars(r, s).map_err(|_err| Error::CoseSignature)?;
            let der = sig_asn.to_der();
            Ok(Vec::from(der.as_bytes()))
        }
        SigningAlg::Es384 => {
            if data.len() != 96 {
                return Err(Error::CoseSignature);
            }

            let mut r = p384::FieldBytes::default();
            let mut s = p384::FieldBytes::default();
            let sig_len = data.len() / 2;

            r.copy_from_slice(&data[0..sig_len]);
            s.copy_from_slice(&data[sig_len..]);

            let sig_asn =
                p384::ecdsa::Signature::from_scalars(r, s).map_err(|_err| Error::CoseSignature)?;
            let der = sig_asn.to_der();
            Ok(Vec::from(der.as_bytes()))
        }
        _ => Ok(Vec::from(data)),
    }
}

// C2PA use P1363 format for EC signatures so we must
// convert from ASN.1 DER to IEEE P1363 format to verify.
struct ECSigComps<'a> {
    r: &'a [u8],
    s: &'a [u8],
}

fn parse_ec_sig(data: &[u8]) -> der_parser::error::BerResult<ECSigComps> {
    parse_der_sequence_defined_g(|content: &[u8], _| {
        let (rem1, r) = parse_der_integer(content)?;
        let (_rem2, s) = parse_der_integer(rem1)?;

        Ok((
            data,
            ECSigComps {
                r: r.as_slice()?,
                s: s.as_slice()?,
            },
        ))
    })(data)
}

fn der_to_p1363(data: &[u8], alg: SigningAlg) -> Result<Vec<u8>> {
    let (_, p) = parse_ec_sig(data).map_err(|_err| Error::InvalidEcdsaSignature)?;

    let mut r = extfmt::Hexlify(p.r).to_string();
    let mut s = extfmt::Hexlify(p.s).to_string();

    let sig_len: usize = match alg {
        SigningAlg::Es256 => 64,
        SigningAlg::Es384 => 96,
        SigningAlg::Es512 => 132,
        _ => return Err(Error::UnsupportedType),
    };

    // pad or truncate as needed
    let rp = if r.len() > sig_len {
        // truncate
        let offset = r.len() - sig_len;
        &r[offset..r.len()]
    } else {
        // pad
        while r.len() != sig_len {
            r.insert(0, '0');
        }
        r.as_ref()
    };

    let sp = if s.len() > sig_len {
        // truncate
        let offset = s.len() - sig_len;
        &s[offset..s.len()]
    } else {
        // pad
        while s.len() != sig_len {
            s.insert(0, '0');
        }
        s.as_ref()
    };

    if rp.len() != sig_len || rp.len() != sp.len() {
        return Err(Error::InvalidEcdsaSignature);
    }

    // merge r and s strings
    let mut new_sig = rp.to_string();
    new_sig.push_str(sp);

    // convert back from hex string to byte array
    (0..new_sig.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&new_sig[i..i + 2], 16).map_err(|_err| Error::InvalidEcdsaSignature)
        })
        .collect()
}

pub(crate) fn ensure_p1363_sig(data: &[u8], alg: SigningAlg) -> Result<Vec<u8>> {
    match alg {
        SigningAlg::Es256 => der_to_p1363(data, alg),
        SigningAlg::Es384 => der_to_p1363(data, alg),
        _ => Ok(Vec::from(data)),
    }
}

/// Extract all certificates `signcert`.
///
/// This function returns at least an empty vector.
pub(crate) fn get_certificates(signcert: &[u8]) -> Vec<Certificate> {
    let mut pem_sections = BufReader::new(signcert);
    let mut signcerts = vec![];
    for item in iter::from_fn(|| read_one(&mut pem_sections).transpose()) {
        match item {
            Ok(item) => {
                if let Item::X509Certificate(cert) = item {
                    signcerts.push(Certificate(cert));
                }
            }
            Err(_e) => {}
        }
    }
    signcerts
}

/// Extract all ec-encoded private keys from `rd`, and return a vec of
/// Certificates containing the der-format contents.
///
/// This function returns at least an empty vector
pub(crate) fn get_ec_private_keys(pkey: &[u8]) -> Result<Vec<Certificate>> {
    let mut reader = BufReader::new(pkey);
    let mut pkeys = vec![];

    // Get private key
    for item in iter::from_fn(|| read_one(&mut reader).transpose()) {
        match item {
            Ok(item) => {
                if let Item::PKCS8Key(cert) = item {
                    pkeys.push(Certificate(cert));
                }
            }
            Err(_e) => {}
        }
    }

    Ok(pkeys)
}
