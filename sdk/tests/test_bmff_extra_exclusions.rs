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

//! `builder.bmff_hash_extra_exclusions`: extra exclusions for the BMFF hash
//! assertions the SDK generates.

use std::io::Cursor;

use c2pa::{assertions::BmffHash, Builder, Context, Error, Reader, Settings, ValidationState};

mod common;
use common::test_signer;

const VIDEO: &[u8] = include_bytes!("fixtures/video1_no_manifest.mp4");
const DEFINITION: &str = r#"{"title":"extra exclusions","assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"}]}}]}"#;

fn settings(extra: &str) -> Settings {
    common::test_settings()
        .with_json(&format!(
            r#"{{"builder":{{"bmff_hash_extra_exclusions":{extra}}}}}"#
        ))
        .unwrap()
}

fn builder(extra: &str) -> Builder {
    Builder::from_context(Context::new().with_settings(settings(extra)).unwrap())
        .with_definition(DEFINITION)
        .unwrap()
}

fn sign(builder: &mut Builder, input: &[u8]) -> c2pa::Result<Vec<u8>> {
    let mut output = Cursor::new(Vec::new());
    builder.sign(
        &test_signer(),
        "video/mp4",
        &mut Cursor::new(input),
        &mut output,
    )?;
    Ok(output.into_inner())
}

fn bmff_hash(reader: &Reader) -> BmffHash {
    let manifest = reader.active_manifest().unwrap();
    for label in ["c2pa.hash.bmff.v3", "c2pa.hash.bmff.v2"] {
        if let Ok(hash) = manifest.find_assertion::<BmffHash>(label) {
            return hash;
        }
    }
    panic!("no BMFF hash assertion");
}

fn signed_hash(signed: &[u8]) -> BmffHash {
    let reader = Reader::default()
        .with_stream("video/mp4", Cursor::new(signed))
        .unwrap();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{reader}"
    );
    bmff_hash(&reader)
}

fn xpaths(hash: &BmffHash) -> Vec<String> {
    hash.exclusions().iter().map(|e| e.xpath.clone()).collect()
}

#[test]
fn empty_list_changes_nothing() {
    let default = xpaths(&signed_hash(&sign(&mut builder("[]"), VIDEO).unwrap()));
    let mut plain = Builder::from_context(
        Context::new()
            .with_settings(common::test_settings())
            .unwrap(),
    )
    .with_definition(DEFINITION)
    .unwrap();
    assert_eq!(
        xpaths(&signed_hash(&sign(&mut plain, VIDEO).unwrap())),
        default
    );
}

#[test]
fn extras_are_appended_once_after_the_defaults() {
    let default = xpaths(&signed_hash(&sign(&mut builder("[]"), VIDEO).unwrap()));
    let signed = sign(
        &mut builder(r#"[{"xpath":"/moov/udta"},{"xpath":"/ftyp"},{"xpath":"/moov/udta"}]"#),
        VIDEO,
    )
    .unwrap();
    let mut expected = default;
    expected.push("/moov/udta".to_owned());
    assert_eq!(xpaths(&signed_hash(&signed)), expected);
}

#[test]
fn excluded_box_is_unbound_and_the_rest_stays_bound() {
    // Exclude a box that exists in the fixture, then change a byte inside it
    // and a byte of media.
    let signed = sign(&mut builder(r#"[{"xpath":"/moov/udta"}]"#), VIDEO).unwrap();
    let udta = find_box(&signed, &[*b"moov", *b"udta"]).expect("fixture has moov/udta");
    let mut tampered = signed.clone();
    // The last byte of udta is payload of its last child, not a box header.
    tampered[udta.1 - 1] ^= 0xff;
    let reader = Reader::default()
        .with_stream("video/mp4", Cursor::new(&tampered))
        .unwrap();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{reader}"
    );

    let mdat = find_box(&signed, &[*b"mdat"]).unwrap();
    let mut tampered = signed;
    tampered[mdat.1 - 1] ^= 0xff;
    let reader = Reader::default()
        .with_stream("video/mp4", Cursor::new(&tampered))
        .unwrap();
    assert_eq!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{reader}"
    );
}

#[test]
fn conditional_entries_round_trip() {
    let signed = sign(
        &mut builder(r#"[{"xpath":"/moov/mvhd","version":0,"subset":[{"offset":20,"length":4}]}]"#),
        VIDEO,
    )
    .unwrap();
    let hash = signed_hash(&signed);
    let extra = hash
        .exclusions()
        .iter()
        .find(|e| e.xpath == "/moov/mvhd")
        .unwrap();
    assert_eq!(extra.version, Some(0));
    let subset = extra.subset.as_ref().unwrap();
    assert_eq!((subset[0].offset, subset[0].length), (20, 4));
}

#[test]
fn placeholder_carries_the_extras() {
    let mut builder = builder(r#"[{"xpath":"/sidx"}]"#);
    builder.placeholder("video/mp4").unwrap();
    // The placeholder's BmffHash is part of the builder's definition.
    let definition = serde_json::to_string(&builder.definition).unwrap();
    assert!(
        definition.contains(r#""xpath":"/sidx""#),
        "placeholder lacks the extra exclusion: {definition}"
    );
}

#[test]
fn caller_supplied_bmff_hash_is_refused() {
    let mut builder = builder(r#"[{"xpath":"/sidx"}]"#);
    let mut supplied = BmffHash::new("jumbf manifest", "sha256", None);
    supplied.set_default_exclusions();
    supplied.set_bmff_version(3);
    builder
        .add_assertion("c2pa.hash.bmff.v3", &supplied)
        .unwrap();
    let result = sign(&mut builder, VIDEO);
    assert!(
        matches!(&result, Err(Error::BadParam(m)) if m.contains("bmff_hash_extra_exclusions")),
        "{result:?}"
    );
}

#[test]
fn invalid_entries_are_refused_when_settings_load() {
    for (extra, why) in [
        (r#"[{"xpath":"sidx"}]"#, "relative path"),
        (r#"[{"xpath":"/si"}]"#, "short box type"),
        (r#"[{"xpath":"/moov//trak"}]"#, "empty path element"),
        (r#"[{"xpath":"/sidx","subset":[]}]"#, "empty subset"),
        (
            r#"[{"xpath":"/sidx","subset":[{"offset":8,"length":8},{"offset":12,"length":4}]}]"#,
            "overlapping subsets",
        ),
        (
            r#"[{"xpath":"/sidx","subset":[{"offset":8,"length":0},{"offset":20,"length":4}]}]"#,
            "open-ended subset before another",
        ),
        (
            r#"[{"xpath":"/sidx","subset":[{"offset":18446744073709551615,"length":2}]}]"#,
            "subset overflow",
        ),
        (r#"[{"xpath":"/sidx","flags":[1]}]"#, "short flags"),
        (r#"[{"xpath":"/sidx","exact":true}]"#, "exact without flags"),
        (r#"[{"xpath":"/sidx","data":[]}]"#, "empty data"),
    ] {
        assert!(
            Settings::new()
                .with_json(&format!(
                    r#"{{"builder":{{"bmff_hash_extra_exclusions":{extra}}}}}"#
                ))
                .is_err(),
            "{why} must be refused"
        );
    }
    let too_many = format!("[{}]", vec![r#"{"xpath":"/sidx"}"#; 65].join(","));
    assert!(Settings::new()
        .with_json(&format!(
            r#"{{"builder":{{"bmff_hash_extra_exclusions":{too_many}}}}}"#
        ))
        .is_err());
}

#[test]
#[cfg(feature = "file_io")]
fn fragmented_files_carry_the_extras() {
    use std::path::{Path, PathBuf};

    let context = Context::new()
        .with_settings(settings(r#"[{"xpath":"/sidx"}]"#))
        .unwrap()
        .into_shared();
    let mut builder = Builder::from_shared_context(&context)
        .with_definition(DEFINITION)
        .unwrap();
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bunny/bunny_89283bps/BigBuckBunny_2s_init.mp4");
    let output = tempfile::tempdir().unwrap();
    builder
        .sign_fragmented_files(
            context.signer().unwrap(),
            input.as_path(),
            Path::new("BigBuckBunny_2s1*.m4s"),
            output.path(),
        )
        .unwrap();
    let rendition = output.path().join("bunny_89283bps");
    let init = std::fs::read(rendition.join("BigBuckBunny_2s_init.mp4")).unwrap();
    let fragment = std::fs::read(rendition.join("BigBuckBunny_2s1.m4s")).unwrap();
    let reader = Reader::from_shared_context(&context)
        .with_fragment("video/mp4", Cursor::new(&init), Cursor::new(&fragment))
        .unwrap();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{reader}"
    );
    let hash = bmff_hash(&reader);
    assert_eq!(xpaths(&hash).iter().filter(|x| *x == "/sidx").count(), 1);
}

/// `(start, end)` of the first box at `path` (root first).
fn find_box(data: &[u8], path: &[[u8; 4]]) -> Option<(usize, usize)> {
    let (mut start, mut end) = (0, data.len());
    let mut found = None;
    for (depth, kind) in path.iter().enumerate() {
        let mut at = start;
        found = None;
        while at + 8 <= end {
            let size = match u32::from_be_bytes(data[at..at + 4].try_into().unwrap()) {
                0 => end - at,
                1 => u64::from_be_bytes(data[at + 8..at + 16].try_into().unwrap()) as usize,
                n => n as usize,
            };
            if size < 8 || at + size > end {
                return None;
            }
            if &data[at + 4..at + 8] == kind {
                found = Some((at, at + size));
                break;
            }
            at += size;
        }
        let (s, e) = found?;
        if depth + 1 < path.len() {
            start = s + 8;
            end = e;
        }
    }
    found
}
