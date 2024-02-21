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

use async_generic::async_generic;

use crate::{error::Result, Builder, CAIRead, Reader, Signer};

/// The main entry point for the v2 API
#[derive(Default)]
pub struct C2pa {
    pub verify: bool,
    pub signer: Option<Box<dyn Signer>>,
}

impl<'a> C2pa {
    /// Create a new instance of the v2 API
    pub fn new() -> Self {
        C2pa {
            verify: true,
            signer: None,
        }
    }

    /// Set the signer to use for signing
    /// # Arguments
    /// * `signer` - The signer to use
    /// # Returns
    pub fn set_signer(mut self, signer: Box<dyn Signer>) -> Self {
        self.signer = Some(signer);
        self
    }

    #[async_generic(async_signature(
        &mut self,
        format: &str,
        stream: &mut dyn CAIRead,
    ))]
    /// Create a manifest store Reader from a stream
    /// # Arguments
    /// * `format` - The format of the stream
    /// * `stream` - The stream to read from
    /// # Returns
    /// A reader for the manifest store
    /// # Errors
    /// If the stream is not a valid manifest store
    pub fn read(&self, format: &str, stream: &mut dyn CAIRead) -> Result<Reader> {
        if _sync {
            Reader::from_stream(format, stream)
        } else {
            Reader::from_stream_async(format, stream).await
        }
    }

    /// Create a new manifest builder for the v2 API
    pub fn builder(&self) -> Builder {
        Builder::new()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use std::path::{Path, PathBuf};

    use super::*;
    use crate::utils::test::{fixture_path, temp_signer};

    fn sign_and_read<P: AsRef<Path>>(c2pa: &C2pa, path: P) -> Result<()> {
        let signer = c2pa
            .signer
            .as_ref()
            .ok_or_else(|| crate::error::Error::BadParam("No signer set for C2pa".to_string()))?;
        let path = path.as_ref();
        let mut file = std::fs::File::open(path)?;
        let extension = path.extension().unwrap().to_str().unwrap();
        let target_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target");
        let dest_path = target_path.join("signed").join(path.file_name().unwrap());
        std::fs::create_dir_all(dest_path.parent().unwrap())?;
        dbg!(dest_path.to_str());
        let mut dest = std::fs::File::create(&dest_path)?;
        c2pa.builder()
            .with_json(
                "{
                \"assertions\": []
            }",
            )?
            .sign(extension, &mut file, &mut dest, signer.as_ref())
            .unwrap();
        let mut dest = std::fs::File::open(&dest_path).unwrap();
        let reader = c2pa.read(extension, &mut dest).unwrap();
        println!("{}", reader.json());
        assert!(reader.status().is_none());
        Ok(())
    }

    #[test]
    fn test_c2pa_new() {
        let signer = temp_signer();
        let c2pa = C2pa::new().set_signer(signer);
        let input_files = [
            "IMG_0003.jpg",
            "libpng-test.png",
            //"TUSCANY.tif",
            "sample1.svg",
            "sample1.webp",
            //"mars.dng",
            //"sample1.heic",
            //"sample1.heif",
            //"sample1.mp3",
            //"video1.mp4",
            //"sample1.avif",
            // "mars.mov",
            //"mars.m4a",
            //"sample1.wav",
            //"basic.pdf"
        ];
        for file in input_files.iter() {
            sign_and_read(&c2pa, fixture_path(file)).expect("Failed to sign and read");
        }
    }

    // #[test]
    // fn test_read_write_manifest_stream() {
    //     let source = crate::utils::test::fixture_path("TUSCANY.TIF");

    //     let mut source = std::fs::File::open(source).unwrap();
    //     let mut dest = std::io::Cursor::new(Vec::new()); //std::fs::File::create(&output).unwrap();
    //     let signer = temp_signer();

    //     Builder::new()
    //         .sign("application/tiff", &mut source, &mut dest, signer.as_ref())
    //         .unwrap();

    //     dest.set_position(0);
    //     // read data back
    //     let reader = Reader::from_stream("image/tiff", &mut dest).unwrap();
    //     assert!(reader.status().is_none());
    // }
}
