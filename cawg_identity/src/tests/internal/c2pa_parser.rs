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

use std::fs;

use hex_literal::hex;

use crate::{internal::c2pa_parser::ManifestStore, tests::fixtures::*, HashedUri};

#[test]
fn basic_case() {
    // Quick proof that we can parse the C2PA JUMBF structure.
    let jumbf: Vec<u8> = fs::read(fixture_path("C.c2pa")).unwrap();

    let ms = ManifestStore::from_slice(&jumbf).unwrap();
    let m = ms.active_manifest().unwrap();
    let claim = m.claim().unwrap();

    assert_eq!(
        claim.claim_generator,
        "make_test_images/0.3.0 c2pa-rs/0.3.0"
    );

    assert_eq!(claim.signature, "self#jumbf=c2pa.signature");

    let mut assertions = claim.assertions.iter();

    assert_eq!(
        assertions.next().unwrap(),
        &HashedUri {
            url: "self#jumbf=c2pa.assertions/c2pa.thumbnail.claim.jpeg".to_owned(),
            alg: None,
            hash: hex!("06 42 3e 40 f7 72 67 57 c4 5c 44 e0 da e3 81 4e 93 39 c2 69 70 c7 e7 ab ab b6 bc 2a 70 d3 3a de").to_vec()
        }
    );

    assert_eq!(
        assertions.next().unwrap(),
        &HashedUri {
            url: "self#jumbf=c2pa.assertions/stds.schema-org.CreativeWork".to_owned(),
            alg: None,
            hash: hex!("40 8f 92 bf 2f 31 3e e9 04 67 68 40 4b a7 48 7a b8 98 42 37 c5 9f 47 ed e7 be 13 6a 09 94 ec 1a").to_vec()
        }
    );

    assert_eq!(
        assertions.next().unwrap(),
        &HashedUri {
            url: "self#jumbf=c2pa.assertions/c2pa.actions".to_owned(),
            alg: None,
            hash: hex!("e3 69 74 99 2b 78 b9 ed 21 22 4e 58 49 9d d0 f1 cc 1c a2 d3 69 85 6b 12 73 0b c3 ca af aa c8 ff").to_vec()
        }
    );

    assert_eq!(
        assertions.next().unwrap(),
        &HashedUri {
            url: "self#jumbf=c2pa.assertions/c2pa.hash.data".to_owned(),
            alg: None,
            hash: hex!("ee 50 52 b3 2e d8 3f 4b 8f 71 ee 6d 0d 8b ef 20 bd a0 08 0f bf 25 83 e6 09 ae 86 1b ff 8b 6d ed").to_vec()
        }
    );

    assert_eq!(claim.alg.unwrap(), "sha256".to_owned());

    assert_eq!(claim.dc_format.unwrap(), "image/jpeg".to_owned());

    assert_eq!(
        claim.instance_id,
        "xmp:iid:e4fbfd18-cb94-42c1-819b-d4f5bb1b4742".to_owned()
    );

    assert_eq!(claim.dc_title.unwrap(), "C.jpg".to_owned());

    let ast = m.assertion_store().unwrap();
    let hash = ast.find_by_label("c2pa.actions").unwrap();
    assert_eq!(hash.desc.label.unwrap(), "c2pa.actions");

    assert!(ast.find_by_label("INVALID.no.such.assertion").is_none());
}

#[test]
fn error_wrong_manifest_store_box_type() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[17] = b'3'; // box type = 'c3pa'

    assert!(ManifestStore::from_slice(&jumbf).is_none());
}

#[test]
fn error_wrong_manifest_store_label() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[36] = b'b'; // label = 'c2pb'

    assert!(ManifestStore::from_slice(&jumbf).is_none());
}

#[test]
fn error_wrong_manifest_box_uuid() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[64] = 1; // wrong UUID

    let ms = ManifestStore::from_slice(&jumbf).unwrap();
    assert!(ms.active_manifest().is_none());
}

#[test]
fn error_wrong_claim_box_uuid() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[0x7ef3] = 1; // wrong UUID

    let ms = ManifestStore::from_slice(&jumbf).unwrap();
    let m = ms.active_manifest().unwrap();

    assert!(m.claim().is_none());
}

#[test]
fn error_wrong_claim_box_type() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[0x7f12] = b'b'; // wrong box type

    let ms = ManifestStore::from_slice(&jumbf).unwrap();
    let m = ms.active_manifest().unwrap();

    assert!(m.claim().is_none());
}

#[test]
fn error_wrong_claim_label() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[0x7f07] = b'x'; // label = "c2paxclaim"

    let ms = ManifestStore::from_slice(&jumbf).unwrap();
    let m = ms.active_manifest().unwrap();

    assert!(m.claim().is_none());
}

#[test]
fn error_invalid_claim_cbor() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[0x7faf] = b'o'; // replace "signature" field name with "signoture"

    let ms = ManifestStore::from_slice(&jumbf).unwrap();
    let m = ms.active_manifest().unwrap();

    assert!(m.claim().is_none());
}

#[test]
fn error_wrong_assertion_store_box_type() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[0x94] = b'x'; // wrong box type

    let ms = ManifestStore::from_slice(&jumbf).unwrap();
    let m = ms.active_manifest().unwrap();

    assert!(m.assertion_store().is_none());
}

#[test]
fn error_wrong_assertion_store_label() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[0xa5] = b'x'; // label = "c2px.assertion_store"

    let ms = ManifestStore::from_slice(&jumbf).unwrap();
    let m = ms.active_manifest().unwrap();

    assert!(m.assertion_store().is_none());
}
