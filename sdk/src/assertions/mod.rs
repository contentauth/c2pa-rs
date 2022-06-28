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

//! Assertion helpers to build, validate, and parse assertions.

mod actions;
pub use actions::*;

mod bmff_hash;
pub use bmff_hash::{BmffHash, DataMap, ExclusionsMap, SubsetMap};

#[allow(dead_code)] // will become public later
mod data_hash;
pub(crate) use data_hash::DataHash;

mod creative_work;
pub use creative_work::CreativeWork;
#[allow(dead_code)] // will become public later
mod ingredient;
pub(crate) use ingredient::{Ingredient, Relationship};

pub mod labels;

mod metadata;
pub use metadata::{Actor, DataSource, Metadata, ReviewRating, *};

mod schema_org;
pub use schema_org::{SchemaDotOrg, SchemaDotOrgPerson};

mod thumbnail;
pub(crate) use thumbnail::Thumbnail;

mod user;
pub use user::User;

mod user_cbor;
pub use user_cbor::UserCbor;

mod uuid_assertion;
pub use uuid_assertion::Uuid;
