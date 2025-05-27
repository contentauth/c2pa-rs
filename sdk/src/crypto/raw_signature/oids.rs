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

#![allow(dead_code)] // Usage varies by platform.

use x509_parser::{der_parser::oid, oid_registry::Oid};

pub(crate) const RSA_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .1);
pub(crate) const RSA_PSS_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .10);

pub(crate) const SHA256_WITH_RSAENCRYPTION_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .11);
pub(crate) const SHA384_WITH_RSAENCRYPTION_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .12);
pub(crate) const SHA512_WITH_RSAENCRYPTION_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .13);

pub(crate) const SHA1_OID: Oid<'static> = oid!(1.3.14 .3 .2 .26);
pub(crate) const SHA256_OID: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .1);
pub(crate) const SHA384_OID: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .2);
pub(crate) const SHA512_OID: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .3);

pub(crate) const EC_PUBLICKEY_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
pub(crate) const ECDSA_WITH_SHA256_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .2);
pub(crate) const ECDSA_WITH_SHA384_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .3);
pub(crate) const ECDSA_WITH_SHA512_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .4);

pub(crate) const SECP521R1_OID: Oid<'static> = oid!(1.3.132 .0 .35);
pub(crate) const SECP384R1_OID: Oid<'static> = oid!(1.3.132 .0 .34);
pub(crate) const PRIME256V1_OID: Oid<'static> = oid!(1.2.840 .10045 .3 .1 .7);

pub(crate) const ED25519_OID: Oid<'static> = oid!(1.3.101 .112);
