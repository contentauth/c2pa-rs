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

use std::{fs::File, path::Path};

use serde_bytes::ByteBuf;

use crate::{
    assertions::{BoxMap, C2PA_BOXHASH},
    asset_io::{
        AssetBoxHash, AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, ComposedManifestRef,
        HashBlockObjectType, HashObjectPositions,
    },
    error::{Error, Result},
};

static SUPPORTED_TYPES: [&str; 3] = [
    "c2pa",
    "application/c2pa",
    "application/x-c2pa-manifest-store",
];

/// Supports working with ".c2pa" files containing only manifest store data
pub struct C2paIO {}

impl CAIReader for C2paIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        asset_reader.rewind()?;

        let mut cai_data = Vec::new();
        // read the whole file
        asset_reader.read_to_end(&mut cai_data)?;
        Ok(cai_data)
    }

    // C2PA files have no xmp data
    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
        None
    }
}

impl CAIWriter for C2paIO {
    fn write_cai(
        &self,
        _input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        // just write the store bytes and ingore the input stream
        output_stream.write_all(store_bytes)?;
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        __input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        // there is no data to hash
        Ok(vec![])
    }

    fn remove_cai_store_from_stream(
        &self,
        _input_stream: &mut dyn CAIRead,
        _output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        // nothing to do here, just return Ok
        Ok(())
    }
}

impl AssetIO for C2paIO {
    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        // just save the data in a file
        std::fs::write(asset_path, store_bytes)
            .map_err(|_err| Error::BadParam("C2PA write error".to_owned()))?;

        Ok(())
    }

    fn get_object_locations(
        &self,
        _asset_path: &std::path::Path,
    ) -> Result<Vec<HashObjectPositions>> {
        let hop = HashObjectPositions {
            offset: 0,
            length: 0,
            htype: HashBlockObjectType::Cai,
        };

        Ok(vec![hop])
    }

    fn remove_cai_store(&self, _asset_path: &Path) -> Result<()> {
        Ok(())
    }

    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        C2paIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(C2paIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(C2paIO::new(asset_type)))
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        Some(self)
    }

    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        Some(self)
    }
}

impl AssetBoxHash for C2paIO {
    fn get_box_map(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<BoxMap>> {
        // creates a box map with only a C2PA box.
        input_stream.rewind()?;
        let alg = "sha256";
        let c2pa_box_map = BoxMap {
            names: vec![C2PA_BOXHASH.to_string()],
            alg: Some(alg.to_string()),
            hash: ByteBuf::from(vec![]),
            excluded: None,
            pad: ByteBuf::from(vec![]),
            range_start: 0,
            range_len: 0,
        };

        let box_maps = vec![c2pa_box_map];
        Ok(box_maps)
    }
}

impl ComposedManifestRef for C2paIO {
    // Return entire CAI block as Vec<u8>
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>> {
        Ok(manifest_data.to_vec())
    }
}

#[cfg(test)]
#[cfg(feature = "file_io")]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::{AssetIO, C2paIO, CAIReader, CAIWriter};
    use crate::{
        crypto::raw_signature::SigningAlg,
        http::SyncGenericResolver,
        settings::Settings,
        status_tracker::{ErrorBehavior, StatusTracker},
        store::Store,
        utils::{
            io_utils::tempdirectory,
            test::{fixture_path, temp_dir_path},
            test_signer::test_signer,
        },
    };

    #[test]
    fn c2pa_io_parse() {
        let settings = Settings::default();
        let http_resolver = SyncGenericResolver::new();

        let path = fixture_path("C.jpg");

        let temp_dir = tempdirectory().expect("temp dir");
        let temp_path = temp_dir_path(&temp_dir, "test.c2pa");

        let c2pa_io = C2paIO {};
        let manifest = crate::jumbf_io::load_jumbf_from_file(&path).expect("read_cai_store");
        c2pa_io
            .save_cai_store(&temp_path, &manifest)
            .expect("save cai store");

        let mut temp_file = std::fs::File::open(&temp_path).expect("open temp file");
        let manifest_2 = c2pa_io.read_cai(&mut temp_file).expect("read cai store");

        assert_eq!(&manifest, &manifest_2);
        // validate against our source stream and the saved / loaded manifest
        let stream = std::fs::File::open(&path).expect("open temp file");
        let store = Store::from_manifest_data_and_stream(
            &manifest,
            "image/jpeg",
            &stream,
            true,
            &mut StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError),
            &http_resolver,
            &settings,
        )
        .expect("loading store");

        let signer = test_signer(SigningAlg::Ps256);

        let manifest2 = store.to_jumbf(signer.as_ref()).expect("to_jumbf");
        assert_eq!(&manifest, &manifest2);
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn c2pa_stream_io() {
        use std::io::{empty, Cursor};
        let path = fixture_path("C.jpg");

        let c2pa_io = C2paIO {};
        let manifest = crate::jumbf_io::load_jumbf_from_file(&path).expect("load_jumbf_from_file");
        let mut output_stream = Cursor::new(Vec::new());
        c2pa_io
            .write_cai(&mut empty(), &mut output_stream, &manifest)
            .expect("write_cai");

        output_stream.set_position(0);
        let manifest2 = c2pa_io.read_cai(&mut output_stream).expect("read_cai");

        assert_eq!(&manifest, &manifest2);
    }
}
