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

use c2pa_raw_crypto::OpenSslMutex;
use openssl::{
    stack::Stack,
    x509::{verify::X509VerifyFlags, X509StoreContext, X509},
};

use super::ChainError;

// OpenSSL X509_V_ERR_CERT_NOT_YET_VALID and X509_V_ERR_CERT_HAS_EXPIRED.
const CERT_NOT_YET_VALID: i32 = 9;
const CERT_HAS_EXPIRED: i32 = 10;

pub(crate) fn check_certificate_trust(
    anchor_ders: &[Vec<u8>],
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
    validation_time: i64,
) -> Result<(), ChainError> {
    let _openssl = OpenSslMutex::acquire()?;
    let mut ca_outside_validity = false;

    let mut cert_chain = Stack::new()?;

    for cert_der in chain_der {
        let x509_cert = X509::from_der(cert_der)?;
        cert_chain.push(x509_cert)?;
    }

    let cert = X509::from_der(cert_der)?;

    let mut builder = openssl::x509::store::X509StoreBuilder::new()?;
    builder.set_flags(X509VerifyFlags::X509_STRICT)?;

    let mut verify_param = openssl::x509::verify::X509VerifyParam::new()?;
    verify_param.set_flags(X509VerifyFlags::X509_STRICT)?;
    verify_param.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?; // allow intermediates to be on anchor list

    verify_param.set_time(validation_time);

    builder.set_param(&verify_param)?;

    // add trust anchors.
    for der in anchor_ders {
        let root_cert = X509::from_der(der)?;
        builder.add_cert(root_cert)?;
    }

    let store = builder.build();

    // try trust anchors
    let mut store_ctx = X509StoreContext::new()?;

    if store_ctx.init(&store, cert.as_ref(), &cert_chain, |f| {
        let verified = f.verify_cert()?;
        let error = f.error().as_raw();

        if !verified
            && f.error_depth() > 0
            && (error == CERT_NOT_YET_VALID || error == CERT_HAS_EXPIRED)
        {
            ca_outside_validity = true;
        }

        Ok(verified)
    })? {
        return Ok(());
    }

    if ca_outside_validity {
        return Err(ChainError::CaCertificateOutsideValidity);
    }

    Err(ChainError::NoAnchorAssociation)
}
