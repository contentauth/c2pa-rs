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
    stack::Stack,
    x509::{verify::X509VerifyFlags, X509StoreContext, X509},
};

use crate::{
    cose::{CertificateTrustError, CertificateTrustPolicy},
    openssl::OpenSslMutex,
};

pub(crate) fn check_certificate_trust(
    ctp: &CertificateTrustPolicy,
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
    signing_time_epoch: Option<i64>,
) -> Result<(), CertificateTrustError> {
    let _openssl = OpenSslMutex::acquire()?;

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

    if let Some(st) = signing_time_epoch {
        verify_param.set_time(st);
    } else {
        verify_param.set_flags(X509VerifyFlags::NO_CHECK_TIME)?;
    }

    builder.set_param(&verify_param)?;

    // Add trust anchors.
    let mut has_anchors = false;
    for der in ctp.trust_anchor_ders() {
        let root_cert = X509::from_der(der)?;
        builder.add_cert(root_cert)?;
        has_anchors = true;
    }

    let store = builder.build();

    if !has_anchors {
        return Err(CertificateTrustError::CertificateNotTrusted);
    }

    let mut store_ctx = X509StoreContext::new()?;
    if store_ctx.init(&store, cert.as_ref(), &cert_chain, |f| f.verify_cert())? {
        Ok(())
    } else {
        Err(CertificateTrustError::CertificateNotTrusted)
    }
}
