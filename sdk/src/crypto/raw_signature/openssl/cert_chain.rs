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

use openssl::x509::X509;

// Verify the certificate chain order.
//
// Return `true` if each cert in the chain can be verified as issued by the next
// issuer.
pub(crate) fn check_chain_order(certs: &[X509]) -> bool {
    // IMPORTANT: ffi_mutex::acquire() should have been called by calling fn. Please
    // don't make this pub or pub(crate) without finding a way to ensure that
    // precondition.

    let mut iter = certs.iter().peekable();

    while let Some(cert) = iter.next() {
        let Some(next) = iter.peek() else {
            break;
        };

        let Ok(pkey) = next.public_key() else {
            return false;
        };

        let Ok(verified) = cert.verify(&pkey) else {
            return false;
        };

        if !verified {
            return false;
        }
    }

    true
}
