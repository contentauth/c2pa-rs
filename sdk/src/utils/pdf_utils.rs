// Copyright 2023 Adobe. All rights reserved.
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

use std::io::Write;

use lopdf::{
    dictionary, Document, Object,
    Object::{Array, Integer, Name, Reference},
    ObjectId, Stream,
};
use thiserror::Error;

// Associated File Relationship
static AF_RELATIONSHIP_KEY: &[u8] = b"AFRelationship";
static ANNOTATIONS_KEY: &[u8] = b"Annots";
static ASSOCIATED_FILE_KEY: &[u8] = b"AF";
static C2PA_RELATIONSHIP: &[u8] = b"C2PA_Manifest";
static CONTENT_CREDS: &str = "Content Credentials";
static EMBEDDED_FILES_KEY: &[u8] = b"EmbeddedFiles";
static SUBTYPE_KEY: &[u8] = b"Subtype";
static NAMES_KEY: &[u8] = b"Names";

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error(transparent)]
    UnableToReadPdf(#[from] lopdf::Error),

    #[error("Unable to add C2PA manifest as an annotation to the PDF.")]
    AddingAnnotation,
}

const C2PA_MIME_TYPE: &str = "application/x-c2pa-manifest-store";

pub(crate) trait C2paPdf: Sized {
    /// Load a PDF from a slice of bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;

    /// Save the `C2paPdf` implementation to the provided `writer`.
    fn save_to<W: Write>(&mut self, writer: &mut W) -> Result<(), std::io::Error>;

    /// Returns `true` if the `PDF` is password protected, `false` otherwise.
    fn is_password_protected(&self) -> bool;

    /// Returns `true` if this PDF has `c2pa` Manifests, `false` otherwise.
    fn has_c2pa_manifest(&self) -> bool;

    /// Writes provided `bytes` as a PDF `Embedded File`
    fn write_manifest_as_embedded_file(&mut self, bytes: Vec<u8>) -> Result<(), Error>;

    /// Writes provided `bytes` as a PDF `Annotation`.
    fn write_manifest_as_annotation(&mut self, vec: Vec<u8>) -> Result<(), Error>;

    /// Returns a reference to the C2PA manifest bytes.
    fn read_manifest_bytes(&self) -> Result<Option<Vec<&[u8]>>, Error>;
}

pub(crate) struct Pdf {
    document: Document,
}

impl C2paPdf for Pdf {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let document = Document::load_mem(bytes)?;
        Ok(Self { document })
    }

    /// Saves the in-memory PDF to the provided `writer`.
    fn save_to<W: Write>(&mut self, writer: &mut W) -> Result<(), std::io::Error> {
        self.document.save_to(writer)
    }

    fn is_password_protected(&self) -> bool {
        self.document.is_encrypted()
    }

    /// Determines if this PDF has a C2PA manifest embedded.
    ///
    /// This is done by checking if the Associated File key of the catalog points to a
    /// [lopdf::Object::Dictionary] with an `AFRelationship` set to `C2PA_Manifest`.
    fn has_c2pa_manifest(&self) -> bool {
        self.document
            .catalog()
            .and_then(|catalog| catalog.get_deref(ASSOCIATED_FILE_KEY, &self.document))
            .and_then(Object::as_dict)
            .and_then(|dict| dict.get_deref(AF_RELATIONSHIP_KEY, &self.document))
            .and_then(Object::as_name)
            .map(|name| name == C2PA_RELATIONSHIP)
            .unwrap_or_default()
    }

    /// Writes the provided `bytes` to the PDF as an `EmbeddedFile`.
    fn write_manifest_as_embedded_file(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        // Add `FileStream` and `FileSpec` to the PDF.
        let file_stream_ref = self.add_c2pa_embedded_file_stream(bytes);
        let file_spec_ref = self.add_embedded_file_specification(file_stream_ref);

        self.set_af_relationship(file_spec_ref)?;

        let mut manifest_name_file_pair = vec![
            Object::string_literal(CONTENT_CREDS),
            Reference(file_spec_ref),
        ];

        let Ok(catalog_names) = self.document.catalog_mut()?.get_mut(NAMES_KEY) else {
            // No /Names key exists in the Catalog. We can safely add the /Names key and construct
            // the remaining objects.
            // Add /EmbeddedFiles dictionary as indirect object.
            let embedded_files_ref = self.document.add_object(dictionary! {
                NAMES_KEY => manifest_name_file_pair
            });

            // Add /Names dictionary as indirect object
            let names_ref = self.document.add_object(dictionary! {
                EMBEDDED_FILES_KEY => Reference(embedded_files_ref)
            });

            // Set /Names key in `Catalog` to reference above indirect object names dictionary.
            self.document.catalog_mut()?.set(NAMES_KEY, names_ref);
            return Ok(());
        };

        // Follows the Reference to the /EmbeddedFiles Dictionary, if the Object is a Reference.
        let names_dictionary = match catalog_names.as_reference() {
            Ok(object_id) => self.document.get_object_mut(object_id)?.as_dict_mut()?,
            _ => catalog_names.as_dict_mut()?,
        };

        let Ok(embedded_files) = names_dictionary.get_mut(EMBEDDED_FILES_KEY) else {
            // We have a /Names dictionary, but are missing the /EmbeddedFiles dictionary
            // and its /Names array of embedded files.
            names_dictionary.set(
                EMBEDDED_FILES_KEY,
                dictionary! { NAMES_KEY => manifest_name_file_pair },
            );
            return Ok(());
        };

        // Follows the reference to the /EmbeddedFiles Dictionary, if the Object is a Reference.
        let embedded_files_dictionary = match embedded_files.as_reference() {
            Ok(object_id) => self.document.get_object_mut(object_id)?.as_dict_mut()?,
            _ => embedded_files.as_dict_mut()?,
        };

        let Ok(names) = embedded_files_dictionary.get_mut(NAMES_KEY) else {
            // This PDF has the /Names dictionary, and it has the /EmbeddedFiles
            // dictionary, but the /EmbeddedFiles Dictionary is missing the /Names Array.
            embedded_files_dictionary.set(
                NAMES_KEY,
                dictionary! { NAMES_KEY => manifest_name_file_pair },
            );

            return Ok(());
        };

        // Follows the reference to the /Names Array, if the Object is a Reference.
        let names_array = match names.as_reference() {
            Ok(object_id) => self.document.get_object_mut(object_id)?.as_array_mut()?,
            _ => names.as_array_mut()?,
        };

        // The PDF has the /Names dictionary, which contains the /EmbeddedFiles Dictionary, which
        // contains the /Names array. Append the manifest's name (Content Credentials)
        // and its reference.
        names_array.append(&mut manifest_name_file_pair);

        Ok(())
    }

    /// Writes the provided bytes to the PDF as a `FileAttachment` `Annotation`. This `Annotation`
    /// is added to the first page of the `PDF`, to the lower left corner.
    fn write_manifest_as_annotation(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        let file_stream_reference = self.add_c2pa_embedded_file_stream(bytes);
        let file_spec_reference = self.add_embedded_file_specification(file_stream_reference);

        self.set_af_relationship(file_spec_reference)?;
        self.add_file_attachment_annotation(file_spec_reference)?;

        Ok(())
    }

    /// Gets a reference to the `C2PA` manifest bytes of the PDF.
    ///
    /// This method will read the bytes of the manifest, whether the manifest was added to the
    /// PDF via an `Annotation` or an `EmbeddedFile`.
    ///
    /// Returns an `Ok(None)` if no manifest is present. Returns a `Ok(Some(Vec<&[u8]>))` when a manifest
    /// is present.
    ///
    /// ### Note:
    ///
    /// A `Vec<&[u8]>` is returned because it's possible for a PDF's manifests to be stored
    /// separately, due to PDF's "Incremental Update" feature. See the spec for more details:
    /// https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html#_embedding_manifests_into_pdfs
    fn read_manifest_bytes(&self) -> Result<Option<Vec<&[u8]>>, Error> {
        if !self.has_c2pa_manifest() {
            return Ok(None);
        };

        Ok(Some(vec![
            &self
                .document
                .catalog()?
                .get_deref(ASSOCIATED_FILE_KEY, &self.document)?
                .as_dict()?
                .get_deref(b"EF", &self.document)?
                .as_stream()?
                .content,
        ]))
    }
}

impl Pdf {
    /// Adds the C2PA `Annotation` to the PDF.
    ///
    /// ### Note:
    /// The `FileAttachment` annotation is added to the first page of the PDF in the lower
    /// left-hand corner. The `FileAttachment`'s location is not defined in the spec as of version
    /// `1.3`.
    fn add_file_attachment_annotation(
        &mut self,
        file_spec_reference: ObjectId,
    ) -> Result<(), Error> {
        let annotation = dictionary! {
            "Type" => Name("Annot".into()),
            "Contents" => Object::string_literal(CONTENT_CREDS),
            "Name" => Object::string_literal(CONTENT_CREDS),
            SUBTYPE_KEY => Name("FileAttachment".into()),
            "FS" => Reference(file_spec_reference),
            // Places annotation in the lower left-hand corner. The icon will be 10x10.
            "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
        };

        // Add C2PA annotation as an indirect object.
        let annotation_ref = self.document.add_object(annotation);

        // Find the reference to the first page of the PDF.
        let first_page_ref = self
            .document
            .page_iter()
            .next()
            .ok_or_else(|| Error::AddingAnnotation)?;

        // Get a mutable ref to the first page as a Dictionary object.
        let first_page = self
            .document
            .get_object_mut(first_page_ref)?
            .as_dict_mut()?;

        // Ensures the /Annots array exists on the page object.
        if !first_page.has(ANNOTATIONS_KEY) {
            first_page.set(ANNOTATIONS_KEY, Array(vec![]))
        }

        // Follows a reference to the indirect annotations array, if it exists.
        let annotation_object = first_page.get_mut(ANNOTATIONS_KEY)?;
        let annotations = if let Ok(v) = annotation_object.as_reference() {
            self.document.get_object_mut(v)?
        } else {
            annotation_object
        }
        .as_array_mut()?;

        annotations.push(Reference(annotation_ref));
        Ok(())
    }

    /// Sets the Associated File (/AF) key of the PDF to the provided embedded file spec reference.
    fn set_af_relationship(&mut self, embedded_file_spec_ref: ObjectId) -> Result<(), Error> {
        self.document
            .catalog_mut()?
            .set(ASSOCIATED_FILE_KEY, embedded_file_spec_ref);

        Ok(())
    }

    /// Adds the `Embedded File Specification` to the PDF document. Returns the [lopdf::Object::Reference]
    /// to the added `Embedded File Specification`.
    fn add_embedded_file_specification(&mut self, file_stream_ref: ObjectId) -> ObjectId {
        let embedded_file_stream = dictionary! {
            AF_RELATIONSHIP_KEY => Name(C2PA_RELATIONSHIP.into()),
            "Desc" => Object::string_literal(CONTENT_CREDS),
            "F" => Object::string_literal(CONTENT_CREDS),
            "EF" => Reference(file_stream_ref),
            "Type" => Name("FileSpec".into()),
            "UF" => Object::string_literal(CONTENT_CREDS),
        };

        self.document.add_object(embedded_file_stream)
    }

    /// Adds the provided `bytes` as a `StreamDictionary` to the PDF document. Returns the
    /// [lopdf::Object::Reference] of the added [lopdf::Object].
    fn add_c2pa_embedded_file_stream(&mut self, bytes: Vec<u8>) -> ObjectId {
        let stream = Stream::new(
            dictionary! {
                SUBTYPE_KEY => C2PA_MIME_TYPE,
                "Length" => Integer(bytes.len() as i64),
            },
            bytes,
        );

        self.document.add_object(stream)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_loads_pdf_from_bytes() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let pdf_result = Pdf::from_bytes(bytes);
        assert!(pdf_result.is_ok());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_loads_pdf_from_bytes_with_invalid_file() {
        let bytes = include_bytes!("../../tests/fixtures/XCA.jpg");
        let pdf_result = Pdf::from_bytes(bytes);
        assert!(matches!(pdf_result, Err(Error::UnableToReadPdf(_))));
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_is_password_protected() {
        let bytes = include_bytes!("../../tests/fixtures/basic-password.pdf");
        let pdf_result = Pdf::from_bytes(bytes).unwrap();
        assert!(pdf_result.is_password_protected());

        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let pdf = Pdf::from_bytes(bytes).unwrap();
        assert!(!pdf.is_password_protected());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_has_c2pa_manifest_on_file_without_manifest() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let pdf = Pdf::from_bytes(bytes).unwrap();
        assert!(!pdf.has_c2pa_manifest())
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_has_c2pa_manifest_on_file_with_manifest() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut pdf = Pdf::from_bytes(bytes).unwrap();
        assert!(!pdf.has_c2pa_manifest());

        pdf.write_manifest_as_annotation(vec![0u8, 1u8]).unwrap();
        assert!(pdf.has_c2pa_manifest());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_adds_embedded_file_spec_to_pdf_stream() {
        let bytes = include_bytes!("../../tests/fixtures/express.pdf");
        let mut pdf = Pdf::from_bytes(bytes).unwrap();
        let object_count_before_add = pdf.document.objects.len();

        let bytes = vec![10u8];
        let id = pdf.add_c2pa_embedded_file_stream(bytes.clone());

        // Object added to the PDF's object collection.
        assert_eq!(object_count_before_add + 1, pdf.document.objects.len());

        // We are able to find the object.
        let stream = pdf.document.get_object(id);
        assert_eq!(stream.unwrap().as_stream().unwrap().content, bytes);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_write_manifest_as_annotation() {
        let mut pdf = Pdf::from_bytes(include_bytes!("../../tests/fixtures/express.pdf")).unwrap();
        assert!(!pdf.has_c2pa_manifest());
        pdf.write_manifest_as_annotation(vec![10u8, 20u8]).unwrap();
        assert!(pdf.has_c2pa_manifest());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_write_manifest_bytes_to_pdf_with_existing_annotations() {
        let mut pdf =
            Pdf::from_bytes(include_bytes!("../../tests/fixtures/basic-annotation.pdf")).unwrap();
        pdf.write_manifest_as_annotation(vec![10u8, 20u8]).unwrap();
        assert!(pdf.has_c2pa_manifest());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_add_manifest_to_embedded_files() {
        let mut pdf = Pdf::from_bytes(include_bytes!("../../tests/fixtures/basic.pdf")).unwrap();
        pdf.write_manifest_as_embedded_file(vec![10u8, 20u8])
            .unwrap();

        assert!(pdf.has_c2pa_manifest());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_add_manifest_to_embedded_files_attachments_present() {
        let mut pdf =
            Pdf::from_bytes(include_bytes!("../../tests/fixtures/basic-attachments.pdf")).unwrap();
        pdf.write_manifest_as_embedded_file(vec![10u8, 20u8])
            .unwrap();

        assert!(pdf.has_c2pa_manifest());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_save_to() {
        let mut pdf = Pdf::from_bytes(include_bytes!("../../tests/fixtures/basic.pdf")).unwrap();
        assert!(!pdf.has_c2pa_manifest());

        pdf.write_manifest_as_annotation(vec![10u8]).unwrap();
        assert!(pdf.has_c2pa_manifest());

        let mut saved_bytes = vec![];
        pdf.save_to(&mut saved_bytes).unwrap();

        let saved_pdf = Pdf::from_bytes(&saved_bytes).unwrap();
        assert!(saved_pdf.has_c2pa_manifest());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_reads_manifest_bytes_for_embedded_files_manifest() {
        let mut pdf = Pdf::from_bytes(include_bytes!("../../tests/fixtures/express.pdf")).unwrap();
        assert!(!pdf.has_c2pa_manifest());

        let manifest_bytes = vec![0u8, 1u8, 1u8, 2u8, 3u8];
        pdf.write_manifest_as_embedded_file(manifest_bytes.clone())
            .unwrap();

        assert!(pdf.has_c2pa_manifest());
        assert!(matches!(
            pdf.read_manifest_bytes(),
            Ok(Some(manifests)) if manifests[0] == manifest_bytes
        ));
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_reads_manifest_bytes_for_annotation_manifest() {
        let mut pdf = Pdf::from_bytes(include_bytes!("../../tests/fixtures/basic.pdf")).unwrap();
        assert!(!pdf.has_c2pa_manifest());

        let manifest_bytes = vec![0u8, 1u8, 1u8, 2u8, 3u8];
        pdf.write_manifest_as_annotation(manifest_bytes.clone())
            .unwrap();

        assert!(pdf.has_c2pa_manifest());
        assert!(matches!(
            pdf.read_manifest_bytes(),
            Ok(Some(manifests)) if manifests[0] == manifest_bytes
        ));
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_read_manifest_bytes_from_pdf_without_bytes_returns_none() {
        let pdf = Pdf::from_bytes(include_bytes!("../../tests/fixtures/basic.pdf")).unwrap();
        assert!(!pdf.has_c2pa_manifest());
        assert!(matches!(pdf.read_manifest_bytes(), Ok(None)));
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_read_manifest_bytes_from_pdf_with_other_af_relationship_returns_none() {
        let mut pdf = Pdf::from_bytes(include_bytes!("../../tests/fixtures/basic.pdf")).unwrap();
        pdf.document
            .catalog_mut()
            .unwrap()
            .set(ASSOCIATED_FILE_KEY, Object::Reference((100, 0)));

        assert!(matches!(pdf.read_manifest_bytes(), Ok(None)));
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_read_pdf_with_associated_file_that_is_not_manifest() {
        let mut pdf = Pdf::from_bytes(include_bytes!("../../tests/fixtures/basic.pdf")).unwrap();
        pdf.document
            .catalog_mut()
            .unwrap()
            .set(ASSOCIATED_FILE_KEY, Object::Reference((100, 0)));

        assert!(matches!(pdf.read_manifest_bytes(), Ok(None)));
    }
}
