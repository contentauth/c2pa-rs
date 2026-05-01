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

use std::{io::Cursor, sync::Arc};

use c2pa::{
    assertions::{c2pa_action, Action, C2paReason},
    settings::Settings,
    Builder, BuilderIntent, Context, Reader,
};
use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::json;

const SOURCE_IMAGE: &[u8] = include_bytes!("../tests/fixtures/earth_apollo17.jpg");
const TEST_SETTINGS: &str = include_str!("../tests/fixtures/test_settings.json");
const FORMAT: &str = "image/jpeg";

fn make_shared_context() -> Arc<Context> {
    let settings = Settings::new()
        .with_json(TEST_SETTINGS)
        .expect("settings");
    Context::new()
        .with_settings(settings)
        .expect("context")
        .into_shared()
}

fn build_signed_with_metadata(shared: &Arc<Context>) -> Vec<u8> {
    let mut builder = Builder::from_shared_context(shared);
    builder.set_intent(BuilderIntent::Create(
        c2pa::DigitalSourceType::DigitalCapture,
    ));
    builder
        .add_assertion(
            "c2pa.metadata",
            &json!({
                "@context": {
                    "exif": "http://ns.adobe.com/exif/1.0/",
                    "tiff": "http://ns.adobe.com/tiff/1.0/"
                },
                "exif:GPSLatitude": "39,21.102N",
                "exif:GPSLongitude": "74,26.5737W",
                "tiff:Make": "CameraCompany",
                "tiff:Model": "Shooter S1"
            }),
        )
        .expect("add_assertion");

    let mut source = Cursor::new(SOURCE_IMAGE);
    let mut signed = Cursor::new(Vec::new());
    builder
        .save_to_stream(FORMAT, &mut source, &mut signed)
        .expect("save_to_stream");
    signed.into_inner()
}

fn build_redacted(shared: &Arc<Context>, signed: &[u8]) -> Vec<u8> {
    let mut signed_cur = Cursor::new(signed.to_vec());
    let reader = Reader::from_shared_context(shared)
        .with_stream(FORMAT, &mut signed_cur)
        .expect("read signed");
    let manifest = reader.active_manifest().expect("manifest");
    let redacted_uri = manifest
        .assertion_references()
        .find(|r| r.url().contains("c2pa.metadata"))
        .map(|r| r.url())
        .expect("metadata uri");

    let mut update = Builder::from_shared_context(shared);
    update.set_intent(BuilderIntent::Update);
    update.definition.redactions = Some(vec![redacted_uri.clone()]);
    let action = Action::new(c2pa_action::REDACTED)
        .set_reason(C2paReason::PiiPresent)
        .set_parameter("redacted", &redacted_uri)
        .expect("action");
    update.add_action(action).expect("add_action");

    signed_cur.set_position(0);
    let mut out = Cursor::new(Vec::new());
    update
        .save_to_stream(FORMAT, &mut signed_cur, &mut out)
        .expect("save redacted");
    out.into_inner()
}

fn read_redacted(c: &mut Criterion) {
    let shared = make_shared_context();
    let signed = build_signed_with_metadata(&shared);
    let redacted = build_redacted(&shared, &signed);

    c.bench_function("read redacted manifest", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&redacted);
            Reader::from_shared_context(&shared)
                .with_stream(FORMAT, &mut stream)
                .expect("read")
        })
    });
}

fn read_baseline(c: &mut Criterion) {
    let shared = make_shared_context();
    let signed = build_signed_with_metadata(&shared);

    c.bench_function("read non-redacted manifest (baseline)", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::from_shared_context(&shared)
                .with_stream(FORMAT, &mut stream)
                .expect("read")
        })
    });
}

criterion_group!(benches, read_redacted, read_baseline);
criterion_main!(benches);
