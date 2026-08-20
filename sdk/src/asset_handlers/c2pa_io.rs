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

use std::path::Path;

use crate::{
    asset_io::{
        AssetBoxHash, AssetIO, BoxMap, C2paReader, C2paWriter, ComposedManifestRef,
        ObjectLocations, ReadSeek, ReadWriteSeek, C2PA_BOXHASH,
    },
    error::{Error, Result},
};

pub(crate) static SUPPORTED_TYPES: [&str; 3] = [
    "c2pa",
    "application/c2pa",
    "application/x-c2pa-manifest-store",
];

/// Supports working with ".c2pa" files containing only manifest store data
pub struct C2paIO {}

impl C2paReader for C2paIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        input_stream.rewind()?;

        let mut cai_data = Vec::new();
        // read the whole file
        input_stream.read_to_end(&mut cai_data)?;
        Ok(cai_data)
    }

    // C2PA files have no xmp data
    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for C2paIO {
    fn write_c2pa(
        &self,
        _input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        // just write the store bytes and ingore the input stream
        output_stream.write_all(store_bytes)?;
        Ok(())
    }

    fn get_object_locations(
        &self,
        __input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        // there is no data to hash
        Ok(vec![])
    }

    fn remove_c2pa(
        &self,
        _input_stream: &mut dyn ReadSeek,
        _output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        // nothing to do here, just return Ok
        Ok(())
    }
}

impl AssetIO for C2paIO {
    fn save_c2pa_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        // just save the data in a file
        std::fs::write(asset_path, store_bytes)
            .map_err(|_err| Error::BadParam("C2PA write error".to_owned()))?;

        Ok(())
    }

    fn remove_c2pa_store(&self, _asset_path: &Path) -> Result<()> {
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

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
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
    fn get_box_map(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<BoxMap>> {
        // creates a box map with only a C2PA box.
        input_stream.rewind()?;
        Ok(vec![BoxMap::new(vec![C2PA_BOXHASH.to_string()], 0, 0)])
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

    use super::{AssetIO, C2paIO, C2paReader, C2paWriter};
    use crate::{
        status_tracker::{ErrorBehavior, StatusTracker},
        store::Store,
        utils::{
            io_utils::tempdirectory,
            test::{fixture_path, temp_dir_path},
            test_signer::test_signer,
        },
        Context, SigningAlg,
    };

    #[test]
    fn c2pa_io_parse() {
        let context = Context::new();

        let path = fixture_path("C.jpg");

        let temp_dir = tempdirectory().expect("temp dir");
        let temp_path = temp_dir_path(&temp_dir, "test.c2pa");

        let c2pa_io = C2paIO {};
        let manifest = context
            .io()
            .read_c2pa_from_file(&path)
            .expect("read_cai_store");
        c2pa_io
            .save_c2pa_store(&temp_path, &manifest)
            .expect("save cai store");

        let mut temp_file = std::fs::File::open(&temp_path).expect("open temp file");
        let manifest_2 = c2pa_io.read_c2pa(&mut temp_file).expect("read cai store");

        assert_eq!(&manifest, &manifest_2);
        // validate against our source stream and the saved / loaded manifest
        let stream = std::fs::File::open(&path).expect("open temp file");
        let store = Store::from_manifest_data_and_stream(
            &manifest,
            "image/jpeg",
            &stream,
            &mut StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError),
            &context,
        )
        .expect("loading store");

        let signer = test_signer(SigningAlg::Ps256);

        let manifest2 = store
            .to_jumbf_internal(signer.reserve_size())
            .expect("to_jumbf");
        assert_eq!(&manifest, &manifest2);
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn c2pa_stream_io() {
        use std::io::{empty, Cursor};
        let path = fixture_path("C.jpg");

        let c2pa_io = C2paIO {};
        let context = Context::new();
        let manifest = context
            .io()
            .read_c2pa_from_file(&path)
            .expect("load_jumbf_from_file");
        let mut output_stream = Cursor::new(Vec::new());
        c2pa_io
            .write_c2pa(&mut empty(), &mut output_stream, &manifest)
            .expect("write_cai");

        output_stream.set_position(0);
        let manifest2 = c2pa_io.read_c2pa(&mut output_stream).expect("read_cai");

        assert_eq!(&manifest, &manifest2);
    }
}
