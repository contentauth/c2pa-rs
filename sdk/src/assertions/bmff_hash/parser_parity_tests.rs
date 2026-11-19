// Copyright 2026 Adobe. All rights reserved.
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

//! The asset-io parser must give `BmffHash` exactly what the legacy parser
//! gives it. Hashing, Merkle and verification code is shared by both, so equal
//! layouts and exclusion ranges mean equal hashes, proofs and results.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::{fs, io::Cursor, path::PathBuf};

use serde_bytes::ByteBuf;

use super::{asset_io_parser, legacy_parser, BmffHash, DataMap, ExclusionsMap, SubsetMap};
use crate::utils::test::fixture_path;

fn bmff_fixtures() -> Vec<PathBuf> {
    let mut directories = vec![fixture_path("")];
    let mut files = Vec::new();
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directories.push(path);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("mp4" | "m4a" | "m4v" | "mov" | "heic" | "heif" | "avif" | "m4s")
            ) {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn defaults() -> Vec<ExclusionsMap> {
    let mut hash = BmffHash::new("parity", "sha256", None);
    hash.set_default_exclusions();
    hash.exclusions().to_vec()
}

fn subset(xpath: &str, subsets: &[(u64, u64)]) -> ExclusionsMap {
    let mut exclusion = ExclusionsMap::new(xpath.into());
    exclusion.subset = Some(
        subsets
            .iter()
            .map(|&(offset, length)| SubsetMap { offset, length })
            .collect(),
    );
    exclusion
}

fn data(xpath: &str, offset: u64, value: &[u8]) -> ExclusionsMap {
    let mut exclusion = ExclusionsMap::new(xpath.into());
    exclusion.data = Some(vec![DataMap {
        offset,
        value: value.to_vec(),
    }]);
    exclusion
}

/// Every kind of selector and predicate, including indexed, malformed and
/// unmatched ones.
fn extended() -> Vec<ExclusionsMap> {
    let mut list = defaults();
    list.push(subset("/moov/trak/mdia/minf/stbl/stco", &[(16, 0)]));
    list.push(subset("/moof/traf", &[(0, 8), (8, 4), (1 << 40, 4)]));
    list.push(ExclusionsMap::new("/meta/iloc".into()));
    list.push(ExclusionsMap::new("/mfra/tfra".into()));
    for exact in [None, Some(false)] {
        let mut tfhd = subset("/moof/traf/tfhd", &[(16, 8)]);
        tfhd.flags = Some(ByteBuf::from([1, 0, 0]));
        tfhd.exact = exact;
        list.push(tfhd);
    }
    let mut short_flags = ExclusionsMap::new("/moov/trak/tkhd".into());
    short_flags.flags = Some(ByteBuf::from([0]));
    list.push(short_flags);
    let mut version = ExclusionsMap::new("/moov/mvhd".into());
    version.version = Some(0);
    list.push(version);
    let mut length = ExclusionsMap::new("/mdat".into());
    length.length = Some(1);
    list.push(length);
    list.push(data("/ftyp", 4, b"ftyp"));
    list.push(data("/ftyp", 4, b"nope"));
    for xpath in [
        "/moov/trak[1]/mdia",
        "/moov/trak[2]",
        "/moov[1]/trak[1]/tkhd",
        "/uuid[2]",
        "/moof[1]/traf[1]/trun",
        "/moov/trak[0]",
        "/moov/trak[x]",
        "/moov/trak[9]",
        "/moov/trak[1]]",
        "/xxxx",
        "/ab",
        "/moov/",
        "",
    ] {
        list.push(ExclusionsMap::new(xpath.into()));
    }
    list
}

/// Compare the parsers on `bytes`; returns how many comparisons both parsed.
/// A readable asset gives at least a layout and two lists for each hash version.
fn assert_same(name: &str, bytes: &[u8]) -> usize {
    let mut compared = 0;
    let legacy = legacy_parser::layout(&mut Cursor::new(bytes));
    let asset_io = asset_io_parser::layout(&mut Cursor::new(bytes));
    match (legacy, asset_io) {
        (Ok(legacy), Ok(asset_io)) => {
            assert_eq!(legacy, asset_io, "{name}: layout");
            compared += 1;
        }
        (Err(_), Err(_)) => {}
        (legacy, asset_io) => panic!("{name}: layout legacy {legacy:?}, asset-io {asset_io:?}"),
    }
    let past_end = vec![data("/mdat", 1 << 40, b"x")];
    for (label, list) in [
        ("default", defaults()),
        ("extended", extended()),
        ("past end", past_end),
    ] {
        for v2 in [false, true] {
            let legacy = legacy_parser::exclusions(&mut Cursor::new(bytes), &list, v2);
            let asset_io = asset_io_parser::exclusions(&mut Cursor::new(bytes), &list, v2);
            match (legacy, asset_io) {
                (Ok(legacy), Ok(asset_io)) => {
                    assert_eq!(legacy, asset_io, "{name}: {label} exclusions, v2 {v2}");
                    compared += 1;
                }
                (Err(_), Err(_)) => {}
                (legacy, asset_io) => panic!(
                    "{name}: {label} exclusions, v2 {v2}: legacy {legacy:?}, asset-io {asset_io:?}"
                ),
            }
        }
    }
    compared
}

#[test]
fn fixtures_parse_the_same() {
    let files = bmff_fixtures();
    assert!(files.iter().any(|f| f.extension().unwrap() == "m4s"));
    let mut compared = 0;
    for path in &files {
        compared += assert_same(&path.display().to_string(), &fs::read(path).unwrap());
    }
    // Each readable file gives a layout and four exclusion lists.
    assert!(
        compared >= (files.len() - 1) * 5,
        "only {compared} comparisons parsed"
    );
}

#[test]
fn assets_with_merkle_proof_boxes_parse_the_same() {
    for fixture in ["video1_no_manifest.mp4", "c.mov", "sample1.heic"] {
        let source = fs::read(fixture_path(fixture)).unwrap();
        for max_proofs in [0, 1, 5] {
            let mut hash = BmffHash::new("parity", "sha256", None);
            hash.set_default_exclusions();
            hash.add_merkle_map_for_mdats(&mut Cursor::new(&source), 16, max_proofs)
                .unwrap();
            let mut output = source.clone();
            if let Some(proofs) = hash.merkle_uuid_boxes() {
                let at = proofs.insertion_point as usize;
                let replaced = at + proofs.replacement_range as usize;
                output.splice(at..replaced, proofs.bytes.iter().copied());
            }
            let compared = assert_same(&format!("{fixture} with {max_proofs} proofs"), &output);
            assert!(compared >= 5, "{fixture}: not every comparison parsed");
        }
    }
}

#[cfg(feature = "file_io")]
#[test]
fn signed_fragments_parse_the_same() {
    use crate::{utils::test::test_context, Builder, BuilderIntent, DigitalSourceType};

    let context = test_context().into_shared();
    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    let output = tempfile::tempdir().unwrap();
    let init = fixture_path("bunny/**/BigBuckBunny_2s_init.mp4");
    builder
        .sign_fragmented_files(
            context.signer().unwrap(),
            init.as_path(),
            std::path::Path::new("BigBuckBunny_2s*.m4s"),
            output.path(),
        )
        .unwrap();
    let mut directories = vec![output.path().to_path_buf()];
    let mut checked = 0;
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directories.push(path);
            } else {
                let compared = assert_same(&path.display().to_string(), &fs::read(&path).unwrap());
                assert!(
                    compared >= 5,
                    "{}: not every comparison parsed",
                    path.display()
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 3, "no signed fragments compared");
}
