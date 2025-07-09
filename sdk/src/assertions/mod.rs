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
pub(crate) use actions::V2_DEPRECATED_ACTIONS;
pub use actions::{c2pa_action, Action, ActionTemplate, Actions, SoftwareAgent};

mod asset_types;
pub use asset_types::{AssetTypeEnum, AssetTypes};

mod bmff_hash;
pub use bmff_hash::{BmffHash, BmffMerkleMap, DataMap, ExclusionsMap, SubsetMap};

mod box_hash;
pub use box_hash::{BoxHash, BoxMap, C2PA_BOXHASH};

mod data_hash;
pub use data_hash::DataHash;

mod creative_work;
pub use creative_work::CreativeWork;

mod exif;
pub use exif::Exif;

#[allow(dead_code)] // will become public later
mod ingredient;
pub(crate) use ingredient::Ingredient;
pub use ingredient::Relationship;

pub mod labels;

mod metadata;
pub use metadata::{
    c2pa_source, Actor, AssetType, DataBox, DataSource, Metadata, ReviewCode, ReviewRating,
};

mod schema_org;
pub use schema_org::{SchemaDotOrg, SchemaDotOrgPerson};

mod thumbnail;
pub(crate) use thumbnail::Thumbnail;

mod timestamp;
pub(crate) use timestamp::TimeStamp;

mod user;
pub(crate) use user::User;

mod user_cbor;
pub(crate) use user_cbor::UserCbor;

mod uuid_assertion;
#[allow(unused_imports)]
pub(crate) use uuid_assertion::Uuid;

mod embedded_data;
pub use embedded_data::EmbeddedData;

pub mod region_of_interest;
