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

use std::io::{self, Cursor};

#[cfg(feature = "file_io")]
use c2pa::Reader;
use c2pa::{Builder, Result};

mod common;
use common::{compare_stream_to_known_good, fixtures_path, test_signer};

#[test]
fn test_builder_ca_jpg() -> Result<()> {
    let manifest_def = std::fs::read_to_string(fixtures_path("simple_manifest.json"))?;
    let mut builder = Builder::from_json(&manifest_def)?;

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut dest = Cursor::new(Vec::new());

    builder.sign(&test_signer(), format, &mut source, &mut dest)?;

    // dest.set_position(0);
    // let path = common::known_good_path("CA_test.json");
    // let reader = c2pa::Reader::from_stream(format, &mut dest)?;
    // std::fs::write(path, reader.json())?;

    dest.set_position(0);
    compare_stream_to_known_good(&mut dest, format, "CA_test.json")
}

// Source: https://github.com/contentauth/c2pa-rs/issues/530
#[test]
fn test_builder_riff() -> Result<()> {
    let manifest_def = include_str!("fixtures/simple_manifest.json");
    let mut source = Cursor::new(include_bytes!("fixtures/sample1.wav"));
    let format = "audio/wav";

    let mut builder = Builder::from_json(manifest_def)?;
    builder.no_embed = true;
    builder.sign(&test_signer(), format, &mut source, &mut io::empty())?;

    Ok(())
}

#[test]
#[cfg(feature = "file_io")]
fn test_builder_fragmented() -> Result<()> {
    use tempfile::tempdir;

    let manifest_def = include_str!("fixtures/simple_manifest.json");
    let mut builder = Builder::from_json(manifest_def)?;
    let tempdir = tempdir().expect("temp dir");
    let output_path = tempdir.into_path();
    let mut init_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    init_path.push("tests/fixtures/bunny/**/BigBuckBunny_2s_init.mp4");
    let pattern = init_path.as_os_str().to_str().unwrap();
    for init in glob::glob(pattern).unwrap() {
        match init {
            Ok(p) => {
                let init_dir = p.parent().unwrap();
                let pattern_path = init_dir.join("BigBuckBunny_2s*.m4s"); // segment match pattern

                // grab the fragments that go with this init segment
                let mut fragments = Vec::new();
                for seg in glob::glob(pattern_path.to_str().unwrap())
                    .unwrap()
                    .flatten()
                {
                    fragments.push(seg);
                }

                dbg!(&fragments);
                // add manifest based on
                let mut new_output_path =
                    output_path.join(p.parent().unwrap().file_name().unwrap());
                new_output_path.push(p.file_name().unwrap());

                builder
                    .sign_fragmented_files(
                        &test_signer(),
                        p.as_path(),
                        &fragments,
                        new_output_path.as_path(),
                    )
                    .unwrap();

                // verify the fragments
                let output_init = new_output_path.join(p.file_name().unwrap());
                let output_fragments = fragments
                    .into_iter()
                    .map(|f| new_output_path.join(f.file_name().unwrap()))
                    .collect();
                let reader = Reader::from_fragmented_files(&output_init, &output_fragments)?;
                //println!("reader: {}", reader);
                assert_eq!(reader.validation_status(), None);

                // test a single fragment
                let init_segment = std::fs::File::open(output_init)?;
                let fragment = std::fs::File::open(output_fragments[0].as_path())?;
                let reader = Reader::from_fragment("video/mp4", init_segment, fragment)?;
                assert_eq!(reader.validation_status(), None);
            }
            Err(e) => panic!("error = {e:?}"),
        }
    }
    Ok(())
}
