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

use openssl::{
    ec::EcKey,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::X509,
};
use x509_parser::der_parser::{
    self,
    der::{parse_der_integer, parse_der_sequence_defined_g},
};

use super::check_chain_order;
use crate::{
    error::{wrap_openssl_err, Error, Result},
    signer::ConfigurableSigner,
    Signer, SigningAlg,
};

/// Implements `Signer` trait using OpenSSL's implementation of
/// ECDSA encryption.
pub struct EcSigner {
    signcerts: Vec<X509>,
    pkey: EcKey<Private>,

    certs_size: usize,
    timestamp_size: usize,

    alg: SigningAlg,
    tsa_url: Option<String>,
}

impl ConfigurableSigner for EcSigner {
    fn from_signcert_and_pkey(
        signcert: &[u8],
        pkey: &[u8],
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self> {
        let certs_size = signcert.len();
        let pkey = EcKey::private_key_from_pem(pkey).map_err(wrap_openssl_err)?;
        let signcerts = X509::stack_from_pem(signcert).map_err(wrap_openssl_err)?;

        // make sure cert chains are in order
        if !check_chain_order(&signcerts) {
            return Err(Error::BadParam(
                "certificate chain is not in correct order".to_string(),
            ));
        }

        Ok(EcSigner {
            signcerts,
            pkey,
            certs_size,
            timestamp_size: 10000, // todo: call out to TSA to get actual timestamp and use that size
            alg,
            tsa_url,
        })
    }
}

impl Signer for EcSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = PKey::from_ec_key(self.pkey.clone()).map_err(wrap_openssl_err)?;

        let mut signer = match self.alg {
            SigningAlg::Es256 => openssl::sign::Signer::new(MessageDigest::sha256(), &key)?,
            SigningAlg::Es384 => openssl::sign::Signer::new(MessageDigest::sha384(), &key)?,
            SigningAlg::Es512 => openssl::sign::Signer::new(MessageDigest::sha512(), &key)?,
            _ => return Err(Error::UnsupportedType),
        };

        signer.update(data).map_err(wrap_openssl_err)?;
        let der_sig = signer.sign_to_vec().map_err(wrap_openssl_err)?;

        der_to_p1363(&der_sig, self.alg)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        let mut certs: Vec<Vec<u8>> = Vec::new();

        for c in &self.signcerts {
            let cert = c.to_der().map_err(wrap_openssl_err)?;
            certs.push(cert);
        }

        Ok(certs)
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }

    fn reserve_size(&self) -> usize {
        1024 + self.certs_size + self.timestamp_size // the Cose_Sign1 contains complete certs and timestamps so account for size
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
    // P1363 format: r | s

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

#[cfg(test)]
#[cfg(feature = "file_io")]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{openssl::temp_signer, utils::test::fixture_path, SigningAlg};

    #[test]
    fn es256_signer() {
        let cert_dir = fixture_path("certs");

        let (signer, _) = temp_signer::get_ec_signer(cert_dir, SigningAlg::Es256, None);

        let data = b"some sample content to sign";
        println!("data len = {}", data.len());

        let signature = signer.sign(data).unwrap();
        println!("signature.len = {}", signature.len());
        assert!(signature.len() >= 64);
        assert!(signature.len() <= signer.reserve_size());
    }

    #[test]
    fn es384_signer() {
        let cert_dir = fixture_path("certs");

        let (signer, _) = temp_signer::get_ec_signer(cert_dir, SigningAlg::Es384, None);

        let data = b"some sample content to sign";
        println!("data len = {}", data.len());

        let signature = signer.sign(data).unwrap();
        println!("signature.len = {}", signature.len());
        assert!(signature.len() >= 64);
        assert!(signature.len() <= signer.reserve_size());
    }

    #[test]
    fn es512_signer() {
        let cert_dir = fixture_path("certs");

        let (signer, _) = temp_signer::get_ec_signer(cert_dir, SigningAlg::Es512, None);

        let data = b"some sample content to sign";
        println!("data len = {}", data.len());

        let signature = signer.sign(data).unwrap();
        println!("signature.len = {}", signature.len());
        assert!(signature.len() >= 64);
        assert!(signature.len() <= signer.reserve_size());
    }
}
