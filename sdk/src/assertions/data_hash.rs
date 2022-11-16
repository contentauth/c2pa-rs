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

use std::path::*;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    asset_io::CAIReadWrite,
    cbor_types::UriT,
    error::{Error, Result},
    utils::hash_utils::{hash_stream_by_alg, verify_asset_by_alg, verify_by_alg, Exclusion},
};

const ASSERTION_CREATION_VERSION: usize = 1;

/// Helper class to create DataHash assertion
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DataHash {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclusions: Option<Vec<Exclusion>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pad: Vec<u8>,

    // must use explicit ByteBuf here because  #[serde(with = "serde_bytes")] does not working if Option<Vec<u8>>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pad2: Option<serde_bytes::ByteBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<UriT>,

    #[serde(skip_deserializing, skip_serializing)]
    pub path: PathBuf,
}

impl DataHash {
    /// Label prefix for a data hash assertion.
    ///
    /// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_data_hash>.
    pub const LABEL: &'static str = labels::DATA_HASH;

    /// Create new DataHash instance
    pub fn new(name: &str, alg: &str, url: Option<UriT>) -> Self {
        DataHash {
            exclusions: None,
            name: Some(name.to_string()),
            alg: Some(alg.to_string()),
            hash: Vec::new(),
            pad: Vec::new(),
            pad2: None,
            url,
            path: PathBuf::new(),
        }
    }

    pub fn add_exclusion(&mut self, exclusion: Exclusion) {
        if self.exclusions.is_none() {
            self.exclusions = Some(Vec::new());
        }

        if let Some(ref mut e) = self.exclusions {
            e.push(exclusion);
        }
    }

    pub fn set_hash(&mut self, hash: Vec<u8>) {
        self.hash = hash;
    }

    pub fn add_padding(&mut self, padding: Vec<u8>) {
        self.pad = padding;
    }

    /// Checks if this is a remote hash
    pub fn is_remote_hash(&self) -> bool {
        self.url.is_some()
    }

    /// generate the hash value for the Asset using the range from the DataHash
    pub fn gen_hash(&mut self, asset_path: &Path) -> Result<()> {
        self.hash = self.hash_from_asset(asset_path)?;
        self.path = PathBuf::from(asset_path);
        Ok(())
    }

    /// generate the hash value for the Asset stream using the range from the DataHash
    pub fn gen_hash_from_stream(&mut self, stream: &mut dyn CAIReadWrite) -> Result<()> {
        self.hash = self.hash_from_stream(stream)?;
        Ok(())
    }

    // add padding to match size
    pub fn pad_to_size(&mut self, desired_size: usize) -> Result<()> {
        let mut curr_size = self.to_assertion()?.data().len();

        // this should not happen
        if curr_size > desired_size {
            return Err(Error::JumbfCreationError);
        }

        let mut last_pad = 0;
        loop {
            if curr_size == desired_size {
                break;
            }

            if desired_size > curr_size {
                self.pad.push(0x0);
                curr_size = self.to_assertion()?.data().len();
                last_pad += 1;
            } else {
                match &self.pad2 {
                    Some(_pad2) => return Err(Error::JumbfCreationError),
                    None => {
                        // if we reach here we need a new second padding object to hit exact size
                        self.pad.clear();
                        let pad2_size = last_pad / 2; // spit across two pads
                        self.pad2 = Some(ByteBuf::from(vec![0u8; pad2_size]));
                        return self.pad_to_size(desired_size);
                    }
                }
            }
        }

        Ok(())
    }

    /// generate the asset hash from a file asset using the constructed
    /// start and length values
    fn hash_from_asset(&mut self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut file = std::fs::File::open(asset_path)?;
        self.hash_from_stream(&mut file)
    }

    /// generate the asset hash from a stream using the constructed
    /// start and length values
    pub fn hash_from_stream(&mut self, stream: &mut dyn CAIReadWrite) -> Result<Vec<u8>> {
        if self.is_remote_hash() {
            return Err(Error::BadParam(
                "asset hash is remote, not yet supported".to_owned(),
            ));
        }

        let alg = match self.alg {
            Some(ref a) => a.clone(),
            None => "sha256".to_string(),
        };

        // sort the exclusions
        let hash = match self.exclusions {
            Some(ref e) => hash_stream_by_alg(&alg, stream, Some(e.clone()))?,
            None => hash_stream_by_alg(&alg, stream, None)?,
        };

        if hash.is_empty() {
            Err(Error::BadParam("could not generate data hash".to_string()))
        } else {
            Ok(hash)
        }
    }

    // verify data using currently set algorithm or default alg is none currently set
    pub fn verify_in_memory_hash(&self, data: &[u8], alg: Option<String>) -> Result<()> {
        if self.is_remote_hash() {
            return Err(Error::BadParam("asset hash is remote".to_owned()));
        }

        let curr_alg = match &self.alg {
            Some(a) => a.clone(),
            None => match alg {
                Some(a) => a,
                None => "sha256".to_string(),
            },
        };

        let exclusions = self.exclusions.as_ref().cloned();

        if verify_by_alg(&curr_alg, &self.hash, data, exclusions) {
            Ok(())
        } else {
            Err(Error::HashMismatch("Hashes do not match".to_owned()))
        }
    }

    ///  Used to verify a DataHash against an asset.
    #[allow(dead_code)] // used in tests
    pub fn verify_hash(&self, asset_path: &Path, alg: Option<&str>) -> Result<()> {
        if self.is_remote_hash() {
            return Err(Error::BadParam("asset hash is remote".to_owned()));
        }

        let curr_alg = alg.unwrap_or("sha256");

        let exclusions = self.exclusions.as_ref().cloned();

        if verify_asset_by_alg(curr_alg, &self.hash, asset_path, exclusions) {
            Ok(())
        } else {
            Err(Error::HashMismatch("Hashes do not match".to_owned()))
        }
    }

    /// Create a new instance from Assertion
    pub fn from_assertion(assertion: &Assertion) -> Result<Self> {
        assertion.check_version_from_label(ASSERTION_CREATION_VERSION)?;
        Self::from_cbor_assertion(assertion)
    }
}

impl AssertionCbor for DataHash {}

impl AssertionBase for DataHash {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn to_assertion(&self) -> Result<Assertion> {
        if self.hash.is_empty() {
            return Err(Error::BadParam(
                "no hash found, gen_hash must be called".to_string(),
            ));
        }
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{
        assertion::{Assertion, AssertionData},
        utils::test::fixture_path,
    };

    #[test]
    fn test_build_assertion() {
        // try json based assertion
        let mut data_hash = DataHash::new("Some data", "sha256", None);
        data_hash.add_exclusion(Exclusion::new(0, 1234));
        data_hash.hash = vec![1, 2, 3];

        let assertion = data_hash.to_assertion().unwrap();

        println!("assertion label: {}", assertion.label());

        let j = assertion.data();

        let from_j = Assertion::from_data_cbor(&assertion.label(), j);
        let ad_ref = from_j.decode_data();

        let _assertion_type = match ad_ref {
            AssertionData::Cbor(ref _ad_cbor) => "cbor",
            AssertionData::Json(ref _ad_json) => "json",
            AssertionData::Binary(ref _ad_bin) => "binary",
            AssertionData::Uuid(_, _) => "uuid",
        };

        if let AssertionData::Cbor(ref ad_cbor) = ad_ref {
            // compare results
            let orig_d = assertion.decode_data();
            if let AssertionData::Cbor(ref orig_cbor) = orig_d {
                // TO DISCUSS: Maurice, I'm not quite sure what we were testing
                // in the original test. LMK if I've lost too much in translation
                // here.
                let orig_as_value: DataHash = serde_cbor::from_slice(orig_cbor).unwrap();
                let ad_as_value: DataHash = serde_cbor::from_slice(ad_cbor).unwrap();

                assert_eq!(orig_as_value, ad_as_value);
            } else {
                panic!("Couldn't decode orig_d");
            }
        } else {
            panic!("Couldn't decode ad_ref");
        }
    }

    #[test]
    fn test_binary_round_trip() {
        let mut data_hash = DataHash::new("Some data", "sha256", None);
        data_hash.add_exclusion(Exclusion::new(0x2000, 0x1000));
        data_hash.add_exclusion(Exclusion::new(0x4000, 0x1000));

        // add some data to hash
        let ap = fixture_path("earth_apollo17.jpg");

        // generate the hash
        data_hash.gen_hash(&ap).unwrap();

        // verify
        data_hash.verify_hash(&ap, None).unwrap();

        let assertion = data_hash.to_assertion().unwrap();

        let orig_bytes = assertion.data();

        let assertion_from_binary = Assertion::from_data_cbor(&assertion.label(), orig_bytes);

        println!(
            "Label Match Test {} = {}",
            assertion.label(),
            assertion_from_binary.label()
        );

        assert_eq!(assertion.label(), assertion_from_binary.label());

        // compare the data as bytes
        assert_eq!(orig_bytes, assertion_from_binary.data());
        println!("Decoded binary matches");
    }
}
