// Copyright 2025 Adobe. All rights reserved.
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

//! Example that builds an example credential matching the one in [§8.1.3,
//! "Identity claims aggregation verifiable credential example,”] of the CAWG
//! identity spec.
//!
//! [§8.1.3, "Identity claims aggregation verifiable credential example,”]: https://cawg.io/identity/1.1-draft+ica-validation/#_identity_claims_aggregation_verifiable_credential_example

use std::str::FromStr;

use chrono::{DateTime, FixedOffset};
use iref::UriBuf;
use non_empty_string::NonEmptyString;
use nonempty_collections::{nev, NEVec};

use crate::{
    claim_aggregation::{IdentityClaimsAggregationVc, IdentityProvider, VerifiedIdentity},
    SignerPayload,
};

pub(crate) fn ica_example() -> IdentityClaimsAggregationVc {
    IdentityClaimsAggregationVc {
        c2pa_asset: SignerPayload {
            referenced_assertions: vec![],
            sig_type: "unknown".to_string(),
            roles: vec![],
        },
        verified_identities: ica_example_identities(),
        time_stamp: None,
    }
}

pub(crate) fn ica_example_identities() -> NEVec<VerifiedIdentity> {
    nev![
        VerifiedIdentity {
            name: Some(NonEmptyString::new("First-Name Last-Name".to_string()).unwrap()),
            type_: NonEmptyString::new("cawg.document_verification".to_string()).unwrap(),
            provider: IdentityProvider {
                id: UriBuf::from_str("https://example-id-verifier.com").unwrap(),
                name: NonEmptyString::new("Example ID Verifier".to_string()).unwrap(),
            },
            address: None,
            uri: None,
            username: None,
            verified_at: "2024-07-26T22:30:15Z"
                .parse::<DateTime<FixedOffset>>()
                .unwrap(),
        },
        VerifiedIdentity {
            name: None,
            type_: NonEmptyString::new("cawg.affiliation".to_string()).unwrap(),
            provider: IdentityProvider {
                id: UriBuf::from_str("https://example-affiliated-organization.com").unwrap(),
                name: NonEmptyString::new("Example Affiliated Organization".to_string()).unwrap(),
            },
            address: None,
            uri: None,
            username: None,
            verified_at: "2024-07-26T22:29:57Z"
                .parse::<DateTime<FixedOffset>>()
                .unwrap(),
        },
        VerifiedIdentity {
            type_: NonEmptyString::new("cawg.social_media".to_string()).unwrap(),
            name: Some(NonEmptyString::new("Silly Cats 929".to_string()).unwrap()),
            username: Some(NonEmptyString::new("username".to_string()).unwrap()),
            uri: Some(UriBuf::from_str("https://example-social-network.com/username").unwrap()),
            provider: IdentityProvider {
                id: UriBuf::from_str("https://example-social-network.com").unwrap(),
                name: NonEmptyString::new("Example Social Network".to_string()).unwrap(),
            },
            address: None,
            verified_at: "2024-05-27T08:40:39.569856Z"
                .parse::<DateTime<FixedOffset>>()
                .unwrap(),
        },
        VerifiedIdentity {
            type_: NonEmptyString::new("cawg.crypto_wallet".to_string()).unwrap(),
            name: None,
            username: Some(NonEmptyString::new("username".to_string()).unwrap()),
            uri: Some(UriBuf::from_str("https://example-crypto-wallet.com/username").unwrap()),
            provider: IdentityProvider {
                id: UriBuf::from_str("https://example-crypto-wallet.com").unwrap(),
                name: NonEmptyString::new("Example Crypto Wallet".to_string()).unwrap(),
            },
            address: None,
            verified_at: "2024-05-27T08:40:39.569856Z"
                .parse::<DateTime<FixedOffset>>()
                .unwrap(),
        }
    ]
}
