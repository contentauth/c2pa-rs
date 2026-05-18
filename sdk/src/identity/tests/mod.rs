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

#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

mod claim_aggregation;
mod examples;
pub(crate) mod fixtures;
mod validation_method;

/// Read a manifest store with identity assertion decoding disabled so the raw
/// assertion bytes are preserved for manual validation in tests.
pub(crate) async fn read_manifest<R: std::io::Read + std::io::Seek + Send>(
    format: &str,
    source: &mut R,
) -> crate::Reader {
    let settings = crate::settings::Settings::default()
        .with_value("core.decode_identity_assertions", false)
        .unwrap();
    let context = crate::Context::new()
        .with_settings(settings)
        .unwrap()
        .into_shared();
    crate::Reader::from_shared_context(&context)
        .with_stream_async(format, source)
        .await
        .unwrap()
}
