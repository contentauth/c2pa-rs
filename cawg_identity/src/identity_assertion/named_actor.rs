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

use std::fmt::Debug;

use chrono::{DateTime, FixedOffset};
use iref::UriBuf;
use non_empty_string::NonEmptyString;

/// A `NamedActor` is the actor named by a signature in an identity
/// assertion.
pub trait NamedActor<'a>: Debug {
    /// Return the name of the subject suitable for user experience display.
    fn display_name(&self) -> Option<String>;

    /// Return `true` if the subject's credentials chain up to a suitable trust
    /// list for this kind of signature.
    fn is_trusted(&self) -> bool;

    /// Return an iterator over the verified identities for this _named actor._
    fn verified_identities(&self) -> VerifiedIdentities;
}

/// Iterator over [`VerifiedIdentity`] structs.
pub type VerifiedIdentities<'a> = Box<dyn Iterator<Item = Box<&'a dyn VerifiedIdentity>> + 'a>;

/// An implementation of `VerifiedIdentity` contains information about
/// the _named actor_ as verified by an _identity provider_ which could be
/// the _identity assertion generator_ or a service contacted by the _identity
/// assertion generator._
pub trait VerifiedIdentity: Debug {
    /// ## Verified identity type
    ///
    /// This property defines the type of verification that was performed by the
    /// _identity provider._
    fn type_(&self) -> VerifiedIdentityType;

    /// ## Display name
    ///
    /// This property MAY be present. If present, it will be a non-empty string
    /// defining the _named actor’s_ name as understood by the _identity
    /// provider._
    fn name(&self) -> Option<NonEmptyString> {
        None
    }

    /// ## User name
    ///
    /// This property MAY be present. If present, it will be a non-empty text
    /// string representing the _named actor’s_ user name as assigned by the
    /// _identity provider._
    fn username(&self) -> Option<NonEmptyString> {
        None
    }

    /// ## Address
    ///
    /// This property MAY be present. If present, it will be non-empty text
    /// string representing the _named actor’s_ cryptographic address as
    /// assigned by the _identity provider.
    fn address(&self) -> Option<NonEmptyString> {
        None
    }

    /// ## URI
    ///
    /// This property MAY be present. If present, it will be a valid URI which
    /// is the primary point of contact for the _named actor_ as assigned by the
    /// _identity provider._
    fn uri(&self) -> Option<UriBuf> {
        None
    }

    /// ## Identity verification date
    ///
    /// This property represents the date and time when the relationship between
    /// the _named actor_ and the _identity provider_ was verified by the
    /// _identity assertion generator._
    fn verified_at(&self) -> DateTime<FixedOffset>;

    // /// ## Identity provider details
    // ///
    // /// The `verifiedIdentities[?].provider` property MUST be an object and MUST
    // /// be present. It contains details about the _identity provider_ and the
    // /// identity verification process.
    // #[ld("cawg:provider")]
    // pub provider: IdentityProvider,
}

/// A `VerifiedIdentityType` contains information about the kind of identity
/// verification that was performed by the _identity provider._
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerifiedIdentityType {
    /// The _identity provider_ has verified one or more government-issued
    /// identity documents presented by the _named actor._
    DocumentVerification,

    /// The _identity provider_ is attesting to the _named actor’s_ membership
    /// in an organization. This could be a professional organization or an
    /// employment relationship.
    Affiliation,

    /// The _named actor_ has demonstrated control over an account (typically a
    /// social media account) hosted by the _identity provider._
    SocialMedia,

    /// The _named actor_ has demonstrated control over an account (typically a
    /// crypto-wallet) hosted by the _identity provider._
    CryptoWallet,

    /// Other string values MAY be used in `verifiedIdentities[?].type` with the
    /// understanding that they may not be well understood by _identity
    /// assertion consumers._ String values for `verifiedIdentities[?].type`
    /// that begin with the prefix `cawg.` are reserved for the use of the
    /// Creator Assertions Working Group and MUST NOT be used unless defined in
    /// a this or a future version of this specification.
    Other(NonEmptyString),
}
