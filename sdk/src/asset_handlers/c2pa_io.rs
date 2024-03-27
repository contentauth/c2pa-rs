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

use crate::{
    asset_io::{
        AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, ComposedManifestRef,
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
        // let hop = HashObjectPositions {
        //     offset: 0,
        //     length: 0,
        //     htype: HashBlockObjectType::Cai,
        // };
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

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        Some(self)
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

    use tempfile::tempdir;

    use super::{AssetIO, C2paIO, CAIReader, CAIWriter};
    use crate::{
        status_tracker::OneShotStatusTracker,
        store::Store,
        utils::test::{fixture_path, temp_dir_path, temp_signer},
    };

    #[test]
    fn c2pa_io_parse() {
        let path = fixture_path("C.jpg");

        let temp_dir = tempdir().expect("temp dir");
        let temp_path = temp_dir_path(&temp_dir, "test.c2pa");

        let c2pa_io = C2paIO {};
        let manifest = crate::jumbf_io::load_jumbf_from_file(&path).expect("read_cai_store");
        c2pa_io
            .save_cai_store(&temp_path, &manifest)
            .expect("save cai store");

        let store = Store::load_from_asset(&temp_path, false, &mut OneShotStatusTracker::new())
            .expect("loading store");

        let signer = temp_signer();

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
