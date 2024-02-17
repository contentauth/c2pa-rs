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

use crate::{error::Result, manifest_store::ManifestStore, Builder, CAIRead, Reader};

/// The main entry point for the v2 API
#[derive(Default)]
pub struct C2pa {
    pub verify: bool,
    //pub _signer: Option<Box<dyn Signer>>,
}

impl C2pa {
    /// Create a new instance of the v2 API
    pub fn new() -> Self {
        C2pa {
            verify: true,
            //_signer: None,
        }
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
        let reader = if _sync {
            ManifestStore::from_stream(format, stream, self.verify)
        } else {
            ManifestStore::from_stream_async(format, stream, self.verify).await
        }?;

        Ok(Reader {
            manifest_store: reader,
        })
    }

    /// Create a new manifest builder for the v2 API
    pub fn builder(&self) -> Builder {
        Builder::new()
    }
}
