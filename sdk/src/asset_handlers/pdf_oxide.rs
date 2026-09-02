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

//! Experimental `pdf_oxide`-backed alternative to the `lopdf`-based [`super::pdf`]. Gated by the
//! `unstable_pdf_oxide` feature; see `docs/experimental-features.md`.
//!
//! Not yet wired into [`super::pdf_io`] or into the [`super::pdf::C2paPdf`] trait — that lands
//! once the write path (adding/removing a manifest) is implemented alongside this read path.

// TODO: Wire `PdfOxideDoc` into `C2paPdf` once the write path is implemented, and remove this.
#![allow(dead_code)]

use std::io::Read;

use pdf_oxide::{
    document::PdfDocument,
    extractors::xmp::XmpExtractor,
    object::{Object, ObjectRef},
};

use super::pdf::Error;

const AF_RELATIONSHIP_KEY: &str = "AFRelationship";
const ASSOCIATED_FILE_KEY: &str = "AF";
const C2PA_RELATIONSHIP: &str = "C2PA_Manifest";
const EMBEDDED_FILE_DICT_KEY: &str = "EF";
const FILE_STREAM_KEY: &str = "F";

pub(crate) struct PdfOxideDoc {
    document: PdfDocument,
    // Decoded C2PA manifest stream bytes, resolved once at construction time and kept here.
    //
    // `pdf_oxide::PdfDocument::load_object`/`catalog` return `Object`s *by value*, unlike
    // `lopdf`'s object graph, which hands back `&Object`s borrowed from the `Document`. There is
    // therefore no borrow of `&self` we could return directly to satisfy `C2paPdf::
    // read_manifest_bytes`'s `&'a self -> Vec<&'a [u8]>` signature, so the bytes are decoded once
    // up front and `read_manifest_bytes` just borrows out of this field.
    manifest_bytes: Option<Vec<u8>>,
}

impl PdfOxideDoc {
    #[allow(dead_code)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let document = PdfDocument::from_bytes(bytes.to_vec())?;
        let mut pdf = Self {
            document,
            manifest_bytes: None,
        };
        pdf.manifest_bytes = pdf.decode_manifest_bytes()?;

        Ok(pdf)
    }

    pub fn from_reader<R: Read>(mut source: R) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    pub fn is_password_protected(&self) -> bool {
        self.document.is_encrypted()
    }

    pub fn has_c2pa_manifest(&self) -> bool {
        self.c2pa_file_spec_reference().is_some()
    }

    pub fn read_manifest_bytes(&self) -> Result<Option<Vec<&[u8]>>, Error> {
        Ok(self.manifest_bytes.as_deref().map(|bytes| vec![bytes]))
    }

    pub fn read_xmp(&self) -> Option<String> {
        XmpExtractor::extract(&self.document)
            .ok()
            .flatten()
            .and_then(|metadata| metadata.raw_xml)
    }

    /// Resolves `obj` if it's an indirect reference, otherwise returns a clone of `obj` as-is.
    fn resolve(&self, obj: &Object) -> Result<Object, Error> {
        match obj.as_reference() {
            Some(reference) => Ok(self.document.load_object(reference)?),
            None => Ok(obj.clone()),
        }
    }

    /// Returns the (resolved) Associated Files array from the PDF's catalog, if present.
    fn associated_files(&self) -> Option<Vec<Object>> {
        let catalog = self.document.catalog().ok()?;
        let af = catalog.as_dict()?.get(ASSOCIATED_FILE_KEY)?.clone();

        self.resolve(&af).ok()?.as_array().cloned()
    }

    /// Returns the [`ObjectRef`] of the C2PA File Spec, if present in the catalog's Associated
    /// Files array.
    fn c2pa_file_spec_reference(&self) -> Option<ObjectRef> {
        self.associated_files()?.into_iter().find_map(|entry| {
            let reference = entry.as_reference()?;
            let file_spec = self.document.load_object(reference).ok()?;
            let relationship = file_spec.as_dict()?.get(AF_RELATIONSHIP_KEY)?.as_name()?;

            (relationship == C2PA_RELATIONSHIP).then_some(reference)
        })
    }

    fn decode_manifest_bytes(&self) -> Result<Option<Vec<u8>>, Error> {
        let Some(file_spec_ref) = self.c2pa_file_spec_reference() else {
            return Ok(None);
        };

        let file_spec = self.document.load_object(file_spec_ref)?;
        let ef = file_spec
            .as_dict()
            .and_then(|dict| dict.get(EMBEDDED_FILE_DICT_KEY))
            .ok_or(Error::UnableToFindEmbeddedFileManifest)?
            .clone();
        let ef = self.resolve(&ef)?;

        let stream = ef
            .as_dict()
            .and_then(|dict| dict.get(FILE_STREAM_KEY))
            .ok_or(Error::UnableToFindEmbeddedFileManifest)?
            .clone();
        let stream = self.resolve(&stream)?;

        Ok(Some(stream.decode_stream_data()?))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_loads_pdf_from_bytes() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let pdf_result = PdfOxideDoc::from_bytes(bytes);
        assert!(pdf_result.is_ok());
    }

    #[test]
    fn test_loads_pdf_from_bytes_with_invalid_file() {
        let bytes = include_bytes!("../../tests/fixtures/XCA.jpg");
        let pdf_result = PdfOxideDoc::from_bytes(bytes);
        assert!(matches!(pdf_result, Err(Error::UnableToReadPdfOxide(_))));
    }

    #[test]
    fn test_is_password_protected() {
        let bytes = include_bytes!("../../tests/fixtures/basic-password.pdf");
        let pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        assert!(pdf.is_password_protected());

        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        assert!(!pdf.is_password_protected());
    }

    #[test]
    fn test_has_c2pa_manifest_on_file_without_manifest() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        assert!(!pdf.has_c2pa_manifest());
    }

    #[test]
    fn test_read_manifest_bytes_from_pdf_without_bytes_returns_none() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        assert!(!pdf.has_c2pa_manifest());
        assert!(matches!(pdf.read_manifest_bytes(), Ok(None)));
    }

    #[test]
    fn test_read_xmp_on_pdf_with_none() {
        let bytes = include_bytes!("../../tests/fixtures/basic-no-xmp.pdf");
        let pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        assert_eq!(pdf.read_xmp(), None);
    }

    #[test]
    fn test_read_xmp_on_pdf_with_some_metadata() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        assert!(pdf.read_xmp().is_some());
    }
}
