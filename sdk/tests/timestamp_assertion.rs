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

use std::io::{Cursor, Seek};

use c2pa::{
    assertions::{self, TimeStamp},
    settings::Settings,
    Builder, BuilderIntent, Reader, Result, Signer,
};

mod common;

const TEST_IMAGE: &[u8] = include_bytes!("fixtures/no_manifest.jpg");
const FORMAT: &str = "image/jpeg";

// Basic wrapper around a Signer to include a time authority URL.
struct WrappedTsaSigner(Box<dyn Signer>);

impl Signer for WrappedTsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.0.sign(data)
    }

    fn alg(&self) -> c2pa::SigningAlg {
        self.0.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.0.certs()
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    fn time_authority_url(&self) -> Option<String> {
        Some("http://timestamp.digicert.com".to_owned())
    }
}

// Sign a manifest with a child ingredient and add the parent manifest
// as a timestamp assertion in the main manifest.
#[test]
fn timestamp_assertion_parent_scope() {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml")).unwrap();

    let mut child_image = Cursor::new(Vec::new());

    let mut builder = Builder::new();
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut Cursor::new(TEST_IMAGE),
            &mut child_image,
        )
        .unwrap();

    Settings::from_toml(
        &toml::toml! {
            [builder.auto_timestamp_assertion]
            enabled = true
            skip_existing = false
            fetch_scope = "parent"
        }
        .to_string(),
    )
    .unwrap();

    child_image.rewind().unwrap();

    let mut parent_image = Cursor::new(Vec::new());

    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Update);
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut child_image,
            &mut parent_image,
        )
        .unwrap();

    parent_image.rewind().unwrap();

    let reader = Reader::from_stream(FORMAT, parent_image).unwrap();
    let timestamp_assertion: TimeStamp = reader
        .active_manifest()
        .unwrap()
        .find_assertion(assertions::labels::TIMESTAMP)
        .unwrap();

    let child_manifest_label = reader.active_manifest().unwrap().ingredients()[0]
        .active_manifest()
        .unwrap();
    assert!(timestamp_assertion
        .get_timestamp(child_manifest_label)
        .is_some());
}

// Sign a manifest with a child ingredient and add all manifests (excluding active)
// as a timestamp assertion in the main manifest.
#[test]
fn timestamp_assertion_all_scope() {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml")).unwrap();

    let mut child_image = Cursor::new(Vec::new());

    let mut builder = Builder::new();
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut Cursor::new(TEST_IMAGE),
            &mut child_image,
        )
        .unwrap();

    Settings::from_toml(
        &toml::toml! {
            [builder.auto_timestamp_assertion]
            enabled = true
            skip_existing = false
            fetch_scope = "all"
        }
        .to_string(),
    )
    .unwrap();

    child_image.rewind().unwrap();

    let mut parent_image = Cursor::new(Vec::new());

    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Update);
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut child_image,
            &mut parent_image,
        )
        .unwrap();

    parent_image.rewind().unwrap();

    let reader = Reader::from_stream(FORMAT, parent_image).unwrap();
    let timestamp_assertion: TimeStamp = reader
        .active_manifest()
        .unwrap()
        .find_assertion(assertions::labels::TIMESTAMP)
        .unwrap();

    let child_manifest_label = reader.active_manifest().unwrap().ingredients()[0]
        .active_manifest()
        .unwrap();
    assert!(timestamp_assertion
        .get_timestamp(child_manifest_label)
        .is_some());
    // Verify the provenance claim isn't included.
    assert!(timestamp_assertion
        .get_timestamp(reader.active_label().unwrap())
        .is_none());
}

// Sign a manifest with a child ingredient and add the ingredient's active manifest label
// as a timestamp assertion in the main manifest.
#[test]
fn timestamp_assertion_explicit_builder() {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml")).unwrap();

    let mut child_image = Cursor::new(Vec::new());

    let mut builder = Builder::new();
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut Cursor::new(TEST_IMAGE),
            &mut child_image,
        )
        .unwrap();

    let mut parent_image = Cursor::new(Vec::new());

    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Update);

    child_image.rewind().unwrap();
    let reader = Reader::from_stream(FORMAT, &mut child_image).unwrap();
    builder.add_timestamp(reader.active_label().unwrap());
    child_image.rewind().unwrap();

    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut child_image,
            &mut parent_image,
        )
        .unwrap();

    parent_image.rewind().unwrap();

    let reader = Reader::from_stream(FORMAT, parent_image).unwrap();
    let timestamp_assertion: TimeStamp = reader
        .active_manifest()
        .unwrap()
        .find_assertion(assertions::labels::TIMESTAMP)
        .unwrap();

    let child_manifest_label = reader.active_manifest().unwrap().ingredients()[0]
        .active_manifest()
        .unwrap();
    assert!(timestamp_assertion
        .get_timestamp(child_manifest_label)
        .is_some());
}

// Sign a manifest with a child ingredient and timestamp assertion it, then sign the parent manifest
// again and skip timestamping all existing timestamped manifests.
#[test]
fn timestamp_assertion_skip_existing() {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml")).unwrap();

    let mut child_image = Cursor::new(Vec::new());

    let mut builder = Builder::new();
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut Cursor::new(TEST_IMAGE),
            &mut child_image,
        )
        .unwrap();

    child_image.rewind().unwrap();

    let mut parent_image = Cursor::new(Vec::new());

    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Update);
    builder
        .sign(
            &common::test_signer(),
            FORMAT,
            &mut child_image,
            &mut parent_image,
        )
        .unwrap();

    Settings::from_toml(
        &toml::toml! {
            [builder.auto_timestamp_assertion]
            enabled = true
            skip_existing = true
            fetch_scope = "all"
        }
        .to_string(),
    )
    .unwrap();

    parent_image.rewind().unwrap();

    let mut parent_parent_image = Cursor::new(Vec::new());

    // Sign it one last time to ensure the original child manifest isn't timestamped again.
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Update);
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut parent_image,
            &mut parent_parent_image,
        )
        .unwrap();

    parent_parent_image.rewind().unwrap();

    let reader = Reader::from_stream(FORMAT, parent_parent_image).unwrap();
    let timestamp_assertion: TimeStamp = reader
        .active_manifest()
        .unwrap()
        .find_assertion(assertions::labels::TIMESTAMP)
        .unwrap();
    assert_eq!(timestamp_assertion.0.len(), 1);

    let parent_manifest_label = reader.active_manifest().unwrap().ingredients()[0]
        .active_manifest()
        .unwrap();
    assert!(timestamp_assertion
        .get_timestamp(parent_manifest_label)
        .is_some());
}
