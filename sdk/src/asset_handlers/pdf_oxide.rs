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
//! `pdf_oxide`'s public API has no support for mutating an already-parsed document (no `/AF`
//! Associated Files support, no "add an object to this document" primitive — see
//! `writer::DocumentEditor`, which only ever produces `/Names/EmbeddedFiles`). Writing is
//! therefore implemented here directly: [`WorkingGraph`] walks the reachable object graph from the
//! trailer, splices in the mutated catalog/manifest objects, and hand-serializes a fresh PDF using
//! `pdf_oxide`'s low-level [`pdf_oxide::writer::ObjectSerializer`] as the only `pdf_oxide` writing
//! primitive involved.

use std::{
    collections::{HashMap, VecDeque},
    io::{Read, Write},
};

use pdf_oxide::{
    document::PdfDocument,
    extractors::xmp::XmpExtractor,
    object::{Object, ObjectRef},
    writer::ObjectSerializer,
};

use super::pdf::{C2paPdf, Error};

const AF_RELATIONSHIP_KEY: &str = "AFRelationship";
const ANNOTATIONS_KEY: &str = "Annots";
const ASSOCIATED_FILE_KEY: &str = "AF";
const C2PA_MIME_TYPE: &str = "application/x-c2pa-manifest-store";
const C2PA_RELATIONSHIP: &str = "C2PA_Manifest";
const CONTENT_CREDS: &str = "Content Credentials";
const EMBEDDED_FILES_KEY: &str = "EmbeddedFiles";
const EMBEDDED_FILE_DICT_KEY: &str = "EF";
const FILE_STREAM_KEY: &str = "F";
const NAMES_KEY: &str = "Names";

pub(crate) struct PdfOxideDoc {
    document: PdfDocument,
    // Current C2PA manifest stream bytes, if any. Populated at construction time (decoded from
    // the original file) and kept in sync by `write_manifest_as_embedded_file` /
    // `write_manifest_as_annotation` / `remove_manifest_bytes`.
    //
    // `pdf_oxide::PdfDocument::load_object`/`catalog` return `Object`s *by value*, unlike
    // `lopdf`'s object graph, which hands back `&Object`s borrowed from the `Document`. There is
    // therefore no borrow of `&self` we could return directly to satisfy `C2paPdf::
    // read_manifest_bytes`'s `&'a self -> Vec<&'a [u8]>` signature, so the bytes are decoded once
    // and `read_manifest_bytes` just borrows out of this field.
    manifest_bytes: Option<Vec<u8>>,
    // Lazily materialized on the first write/remove call. `pdf_oxide` has no API for mutating an
    // already-parsed `PdfDocument`, so writing works against this separate, fully-owned copy of
    // the reachable object graph instead; `save_to` serializes it directly if present, or else
    // passes the original bytes through unchanged.
    working_graph: Option<WorkingGraph>,
}

impl PdfOxideDoc {
    #[allow(dead_code)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let document = PdfDocument::from_bytes(bytes.to_vec())?;
        let mut pdf = Self {
            document,
            manifest_bytes: None,
            working_graph: None,
        };
        pdf.manifest_bytes = pdf.decode_manifest_bytes()?;

        Ok(pdf)
    }

    pub fn from_reader<R: Read>(mut source: R) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
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

    /// Returns the lazily-built [`WorkingGraph`], building it from `self.document` on first call.
    fn working_graph_mut(&mut self) -> Result<&mut WorkingGraph, Error> {
        match self.working_graph {
            Some(ref mut graph) => Ok(graph),
            None => {
                let graph = WorkingGraph::from_document(&self.document)?;
                Ok(self.working_graph.insert(graph))
            }
        }
    }
}

impl C2paPdf for PdfOxideDoc {
    fn save_to<W: Write + 'static>(&mut self, writer: &mut W) -> Result<(), std::io::Error> {
        match &self.working_graph {
            Some(graph) => graph.serialize_to(writer),
            // No writes staged: pass the original bytes through unchanged rather than
            // re-serializing (which `lopdf`'s `save_to` always does, even with no changes).
            None => writer.write_all(&self.document.source_bytes),
        }
    }

    fn is_password_protected(&self) -> bool {
        self.document.is_encrypted()
    }

    fn has_c2pa_manifest(&self) -> bool {
        self.manifest_bytes.is_some()
    }

    fn write_manifest_as_embedded_file(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        let graph = self.working_graph_mut()?;
        let filespec_ref = graph.add_manifest_objects(bytes.clone());
        graph.push_associated_file(filespec_ref);
        graph.add_embedded_file_entry(filespec_ref);
        self.manifest_bytes = Some(bytes);

        Ok(())
    }

    fn write_manifest_as_annotation(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        let graph = self.working_graph_mut()?;
        let filespec_ref = graph.add_manifest_objects(bytes.clone());
        graph.push_associated_file(filespec_ref);
        graph.add_file_attachment_annotation(filespec_ref)?;
        self.manifest_bytes = Some(bytes);

        Ok(())
    }

    fn read_manifest_bytes(&self) -> Result<Option<Vec<&[u8]>>, Error> {
        Ok(self.manifest_bytes.as_deref().map(|bytes| vec![bytes]))
    }

    fn remove_manifest_bytes(&mut self) -> Result<(), Error> {
        if !self.has_c2pa_manifest() {
            return Err(Error::NoManifest);
        }

        self.working_graph_mut()?.remove_manifest()?;
        self.manifest_bytes = None;

        Ok(())
    }

    fn read_xmp(&self) -> Option<String> {
        XmpExtractor::extract(&self.document)
            .ok()
            .flatten()
            .and_then(|metadata| metadata.raw_xml)
    }
}

/// A fully-owned copy of the PDF's reachable object graph (everything reachable from the
/// trailer's `/Root` and `/Info`), used to stage manifest writes/removals and hand-serialize the
/// result. See the module doc for why this exists instead of mutating `PdfDocument` in place.
struct WorkingGraph {
    objects: HashMap<ObjectRef, Object>,
    catalog_ref: ObjectRef,
    next_object_id: u32,
    version: (u8, u8),
}

impl WorkingGraph {
    fn from_document(document: &PdfDocument) -> Result<Self, Error> {
        let trailer_dict = document.trailer().as_dict().ok_or_else(|| {
            Error::from(pdf_oxide::Error::InvalidPdf(
                "trailer is not a dictionary".to_string(),
            ))
        })?;

        let root = trailer_dict.get("Root").ok_or_else(|| {
            Error::from(pdf_oxide::Error::InvalidPdf(
                "trailer is missing /Root".to_string(),
            ))
        })?;
        let catalog_ref = root.as_reference().ok_or_else(|| {
            Error::from(pdf_oxide::Error::InvalidPdf(
                "/Root is not a reference".to_string(),
            ))
        })?;

        let mut objects: HashMap<ObjectRef, Object> = HashMap::new();
        let mut queue: VecDeque<ObjectRef> = VecDeque::new();
        enqueue_references(root, &mut queue);
        if let Some(info) = trailer_dict.get("Info") {
            enqueue_references(info, &mut queue);
        }

        while let Some(object_ref) = queue.pop_front() {
            if objects.contains_key(&object_ref) {
                continue;
            }

            let obj = document.load_object(object_ref)?;
            enqueue_references(&obj, &mut queue);
            objects.insert(object_ref, obj);
        }

        let next_object_id = objects.keys().map(|r| r.id).max().map_or(1, |id| id + 1);

        Ok(Self {
            objects,
            catalog_ref,
            next_object_id,
            version: document.version(),
        })
    }

    fn allocate_id(&mut self) -> ObjectRef {
        let id = self.next_object_id;
        self.next_object_id += 1;

        ObjectRef::new(id, 0)
    }

    fn dict_mut(&mut self, object_ref: ObjectRef) -> Option<&mut HashMap<String, Object>> {
        match self.objects.get_mut(&object_ref) {
            Some(Object::Dictionary(dict)) => Some(dict),
            _ => None,
        }
    }

    /// Resolves `value` one level of indirection deep using the already-collected graph.
    fn resolve_owned(&self, value: &Object) -> Object {
        match value.as_reference().and_then(|r| self.objects.get(&r)) {
            Some(resolved) => resolved.clone(),
            None => value.clone(),
        }
    }

    /// Returns the (resolved) value of `key` in the dictionary at `object_ref`, if present.
    fn resolved_value(&self, object_ref: ObjectRef, key: &str) -> Option<Object> {
        let Object::Dictionary(dict) = self.objects.get(&object_ref)? else {
            return None;
        };

        dict.get(key).map(|value| self.resolve_owned(value))
    }

    fn c2pa_file_spec_reference(&self) -> Option<ObjectRef> {
        let Some(Object::Array(entries)) = self.resolved_value(self.catalog_ref, ASSOCIATED_FILE_KEY)
        else {
            return None;
        };

        entries.into_iter().find_map(|entry| {
            let reference = entry.as_reference()?;
            let Object::Dictionary(dict) = self.objects.get(&reference)? else {
                return None;
            };
            let relationship = dict.get(AF_RELATIONSHIP_KEY)?.as_name()?;

            (relationship == C2PA_RELATIONSHIP).then_some(reference)
        })
    }

    /// Returns every leaf page's [`ObjectRef`], in document order, by walking the page tree from
    /// the catalog's `/Pages` entry.
    fn all_page_references(&self) -> Vec<ObjectRef> {
        let mut pages = Vec::new();

        let Some(Object::Dictionary(catalog_dict)) = self.objects.get(&self.catalog_ref) else {
            return pages;
        };
        let Some(pages_ref) = catalog_dict.get("Pages").and_then(Object::as_reference) else {
            return pages;
        };

        self.collect_page_references(pages_ref, &mut pages, 0);

        pages
    }

    fn collect_page_references(&self, node_ref: ObjectRef, pages: &mut Vec<ObjectRef>, depth: usize) {
        // Guards against a pathological or cyclic page tree; real documents nest a handful of
        // levels deep at most.
        if depth > 64 {
            return;
        }

        let Some(Object::Dictionary(dict)) = self.objects.get(&node_ref) else {
            return;
        };

        match dict.get("Kids").and_then(Object::as_array) {
            Some(kids) => {
                for kid in kids {
                    if let Some(kid_ref) = kid.as_reference() {
                        self.collect_page_references(kid_ref, pages, depth + 1);
                    }
                }
            }
            None => pages.push(node_ref),
        }
    }

    /// Adds the C2PA manifest as an `EmbeddedFile` stream + `Filespec`. Returns the `Filespec`'s
    /// [`ObjectRef`], which the caller still needs to reference from `/AF` and/or an annotation.
    fn add_manifest_objects(&mut self, bytes: Vec<u8>) -> ObjectRef {
        let stream_ref = self.allocate_id();
        let filespec_ref = self.allocate_id();

        let mut stream_dict = HashMap::new();
        stream_dict.insert("Type".to_string(), Object::Name("EmbeddedFile".to_string()));
        stream_dict.insert(
            "Subtype".to_string(),
            Object::Name(C2PA_MIME_TYPE.replace('/', "#2F")),
        );
        self.objects.insert(
            stream_ref,
            Object::Stream {
                dict: stream_dict,
                data: bytes.into(),
            },
        );

        let mut ef_dict = HashMap::new();
        ef_dict.insert(FILE_STREAM_KEY.to_string(), Object::Reference(stream_ref));

        let mut filespec_dict = HashMap::new();
        filespec_dict.insert("Type".to_string(), Object::Name("Filespec".to_string()));
        filespec_dict.insert("F".to_string(), Object::text_string(CONTENT_CREDS));
        filespec_dict.insert("UF".to_string(), Object::text_string(CONTENT_CREDS));
        filespec_dict.insert("Desc".to_string(), Object::text_string(CONTENT_CREDS));
        filespec_dict.insert(EMBEDDED_FILE_DICT_KEY.to_string(), Object::Dictionary(ef_dict));
        filespec_dict.insert(
            AF_RELATIONSHIP_KEY.to_string(),
            Object::Name(C2PA_RELATIONSHIP.to_string()),
        );
        self.objects
            .insert(filespec_ref, Object::Dictionary(filespec_dict));

        filespec_ref
    }

    /// Appends `filespec_ref` to the catalog's `/AF` (Associated Files) array.
    fn push_associated_file(&mut self, filespec_ref: ObjectRef) {
        let mut af_array = match self.resolved_value(self.catalog_ref, ASSOCIATED_FILE_KEY) {
            Some(Object::Array(items)) => items,
            _ => Vec::new(),
        };
        af_array.push(Object::Reference(filespec_ref));

        if let Some(dict) = self.dict_mut(self.catalog_ref) {
            dict.insert(ASSOCIATED_FILE_KEY.to_string(), Object::Array(af_array));
        }
    }

    /// Adds `filespec_ref` to the catalog's `/Names /EmbeddedFiles /Names` tree, creating any of
    /// those dictionaries/arrays that don't already exist.
    ///
    /// Note: if `/Names` and/or `/EmbeddedFiles` already existed as *indirect* objects, this
    /// flattens them to direct (inline) dictionaries in the rewritten catalog. That's a
    /// structural simplification of an already-full-rewrite save, and is spec-legal (PDF readers
    /// don't require these to be indirect).
    fn add_embedded_file_entry(&mut self, filespec_ref: ObjectRef) {
        let manifest_name_pair = vec![Object::text_string(CONTENT_CREDS), Object::Reference(filespec_ref)];

        let mut names_dict = match self.resolved_value(self.catalog_ref, NAMES_KEY) {
            Some(Object::Dictionary(dict)) => dict,
            _ => HashMap::new(),
        };
        let mut embedded_files_dict = match names_dict.get(EMBEDDED_FILES_KEY) {
            Some(value) => match self.resolve_owned(value) {
                Object::Dictionary(dict) => dict,
                _ => HashMap::new(),
            },
            None => HashMap::new(),
        };
        let mut names_array = match embedded_files_dict.get(NAMES_KEY) {
            Some(value) => match self.resolve_owned(value) {
                Object::Array(items) => items,
                _ => Vec::new(),
            },
            None => Vec::new(),
        };

        names_array.extend(manifest_name_pair);
        embedded_files_dict.insert(NAMES_KEY.to_string(), Object::Array(names_array));
        names_dict.insert(
            EMBEDDED_FILES_KEY.to_string(),
            Object::Dictionary(embedded_files_dict),
        );

        if let Some(catalog_dict) = self.dict_mut(self.catalog_ref) {
            catalog_dict.insert(NAMES_KEY.to_string(), Object::Dictionary(names_dict));
        }
    }

    /// Adds a `FileAttachment` annotation referencing `filespec_ref` to the first page, in the
    /// lower-left corner (mirroring [`super::pdf::Pdf::add_file_attachment_annotation`]).
    fn add_file_attachment_annotation(&mut self, filespec_ref: ObjectRef) -> Result<(), Error> {
        let first_page_ref = self
            .all_page_references()
            .into_iter()
            .next()
            .ok_or(Error::AddingAnnotation)?;

        let annotation_ref = self.allocate_id();
        let mut annotation_dict = HashMap::new();
        annotation_dict.insert("Type".to_string(), Object::Name("Annot".to_string()));
        annotation_dict.insert("Contents".to_string(), Object::text_string(CONTENT_CREDS));
        annotation_dict.insert("Name".to_string(), Object::text_string(CONTENT_CREDS));
        annotation_dict.insert(
            "Subtype".to_string(),
            Object::Name("FileAttachment".to_string()),
        );
        annotation_dict.insert("FS".to_string(), Object::Reference(filespec_ref));
        annotation_dict.insert(
            "Rect".to_string(),
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(10),
                Object::Integer(10),
            ]),
        );
        self.objects
            .insert(annotation_ref, Object::Dictionary(annotation_dict));

        let mut annots = match self.resolved_value(first_page_ref, ANNOTATIONS_KEY) {
            Some(Object::Array(items)) => items,
            _ => Vec::new(),
        };
        annots.push(Object::Reference(annotation_ref));

        if let Some(page_dict) = self.dict_mut(first_page_ref) {
            page_dict.insert(ANNOTATIONS_KEY.to_string(), Object::Array(annots));
        }

        Ok(())
    }

    /// Removes the C2PA manifest, wherever it's referenced from (`/AF`, `/Names/EmbeddedFiles`,
    /// and/or a page's `/Annots`), and drops its Filespec + stream objects.
    fn remove_manifest(&mut self) -> Result<(), Error> {
        let filespec_ref = self.c2pa_file_spec_reference().ok_or(Error::NoManifest)?;

        let stream_ref = match self.resolved_value(filespec_ref, EMBEDDED_FILE_DICT_KEY) {
            Some(Object::Dictionary(dict)) => {
                dict.get(FILE_STREAM_KEY).and_then(Object::as_reference)
            }
            _ => None,
        };

        if let Some(Object::Array(af)) = self.resolved_value(self.catalog_ref, ASSOCIATED_FILE_KEY) {
            let filtered: Vec<Object> = af
                .into_iter()
                .filter(|entry| entry.as_reference() != Some(filespec_ref))
                .collect();
            if let Some(catalog_dict) = self.dict_mut(self.catalog_ref) {
                catalog_dict.insert(ASSOCIATED_FILE_KEY.to_string(), Object::Array(filtered));
            }
        }

        if let Some(Object::Dictionary(mut names_dict)) =
            self.resolved_value(self.catalog_ref, NAMES_KEY)
        {
            if let Some(Object::Dictionary(mut embedded_files_dict)) = names_dict
                .get(EMBEDDED_FILES_KEY)
                .map(|value| self.resolve_owned(value))
            {
                if let Some(Object::Array(mut names_array)) = embedded_files_dict
                    .get(NAMES_KEY)
                    .map(|value| self.resolve_owned(value))
                {
                    if let Some(idx) = names_array
                        .iter()
                        .position(|v| v.as_reference() == Some(filespec_ref))
                    {
                        // The array is a flat [name, ref, name, ref, ...] list; drop the pair.
                        let name_idx = idx.saturating_sub(1);
                        names_array.drain(name_idx..=idx);
                    }
                    embedded_files_dict.insert(NAMES_KEY.to_string(), Object::Array(names_array));
                    names_dict.insert(
                        EMBEDDED_FILES_KEY.to_string(),
                        Object::Dictionary(embedded_files_dict),
                    );
                    if let Some(catalog_dict) = self.dict_mut(self.catalog_ref) {
                        catalog_dict.insert(NAMES_KEY.to_string(), Object::Dictionary(names_dict));
                    }
                }
            }
        }

        for page_ref in self.all_page_references() {
            let Some(Object::Array(annots)) = self.resolved_value(page_ref, ANNOTATIONS_KEY) else {
                continue;
            };

            let filtered: Vec<Object> = annots
                .into_iter()
                .filter(|annot| {
                    let Some(annot_ref) = annot.as_reference() else {
                        return true;
                    };
                    let is_match = matches!(
                        self.objects.get(&annot_ref),
                        Some(Object::Dictionary(dict))
                            if dict.get("FS").and_then(Object::as_reference) == Some(filespec_ref)
                    );

                    !is_match
                })
                .collect();

            if let Some(page_dict) = self.dict_mut(page_ref) {
                page_dict.insert(ANNOTATIONS_KEY.to_string(), Object::Array(filtered));
            }
        }

        self.objects.remove(&filespec_ref);
        if let Some(stream_ref) = stream_ref {
            self.objects.remove(&stream_ref);
        }

        Ok(())
    }

    /// Hand-serializes a full rewrite of the PDF: header, every reachable object (each written
    /// via `pdf_oxide`'s `ObjectSerializer`, the only low-level writing primitive it exposes),
    /// then a classic cross-reference table and trailer.
    fn serialize_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let serializer = ObjectSerializer::new();
        let mut buf: Vec<u8> = Vec::new();

        writeln!(buf, "%PDF-{}.{}", self.version.0, self.version.1)?;
        // Binary marker comment (4 bytes >= 0x80), conventional practice signaling binary content
        // to readers that sniff the first few lines.
        buf.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");

        let mut entries: Vec<(&ObjectRef, &Object)> = self.objects.iter().collect();
        entries.sort_by_key(|(object_ref, _)| object_ref.id);

        let mut offsets: HashMap<u32, (u16, u64)> = HashMap::new();
        for (object_ref, obj) in entries {
            offsets.insert(object_ref.id, (object_ref.gen, buf.len() as u64));
            buf.extend_from_slice(&serializer.serialize_indirect(object_ref.id, object_ref.gen, obj));
        }

        let xref_offset = buf.len() as u64;
        let size = offsets.keys().max().copied().unwrap_or(0) + 1;

        // Classic (non-cross-reference-stream) xref table. Per ISO 32000-1 7.5.4, each entry is
        // exactly 20 bytes: 10-digit offset, space, 5-digit generation, space, 'n'/'f', 2-byte EOL.
        writeln!(buf, "xref")?;
        writeln!(buf, "0 {size}")?;
        write!(buf, "0000000000 65535 f\r\n")?;
        for id in 1..size {
            match offsets.get(&id) {
                Some(&(gen, offset)) => write!(buf, "{offset:010} {gen:05} n\r\n")?,
                None => write!(buf, "0000000000 00000 f\r\n")?,
            }
        }

        writeln!(buf, "trailer")?;
        writeln!(buf, "<< /Size {size} /Root {} 0 R >>", self.catalog_ref.id)?;
        writeln!(buf, "startxref")?;
        writeln!(buf, "{xref_offset}")?;
        write!(buf, "%%EOF")?;

        writer.write_all(&buf)
    }
}

/// Recursively enqueues every [`ObjectRef`] reachable from `obj`'s own structure (a purely
/// syntactic walk: dictionaries, arrays, and stream dictionaries all get recursed into, regardless
/// of what their keys mean). Cross-object recursion is handled by the caller's queue + visited-set
/// (see [`WorkingGraph::from_document`]); this only recurses within a single object's own nesting.
fn enqueue_references(obj: &Object, queue: &mut VecDeque<ObjectRef>) {
    match obj {
        Object::Reference(reference) => queue.push_back(*reference),
        Object::Dictionary(dict) => {
            for value in dict.values() {
                enqueue_references(value, queue);
            }
        }
        Object::Array(items) => {
            for item in items {
                enqueue_references(item, queue);
            }
        }
        Object::Stream { dict, .. } => {
            for value in dict.values() {
                enqueue_references(value, queue);
            }
        }
        _ => {}
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

    #[test]
    fn test_has_c2pa_manifest_on_file_with_manifest() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        assert!(!pdf.has_c2pa_manifest());

        pdf.write_manifest_as_annotation(vec![0u8, 1u8]).unwrap();
        assert!(pdf.has_c2pa_manifest());
    }

    #[test]
    fn test_write_manifest_as_annotation() {
        let bytes = include_bytes!("../../tests/fixtures/express.pdf");
        let mut pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        assert!(!pdf.has_c2pa_manifest());
        pdf.write_manifest_as_annotation(vec![10u8, 20u8]).unwrap();
        assert!(pdf.has_c2pa_manifest());
    }

    #[test]
    fn test_write_manifest_bytes_to_pdf_with_existing_annotations() {
        let bytes = include_bytes!("../../tests/fixtures/basic-annotation.pdf");
        let mut pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        pdf.write_manifest_as_annotation(vec![10u8, 20u8]).unwrap();
        assert!(pdf.has_c2pa_manifest());
    }

    #[test]
    fn test_add_manifest_to_embedded_files() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        pdf.write_manifest_as_embedded_file(vec![10u8, 20u8])
            .unwrap();

        assert!(pdf.has_c2pa_manifest());
    }

    #[test]
    fn test_add_manifest_to_embedded_files_attachments_present() {
        let bytes = include_bytes!("../../tests/fixtures/basic-attachments.pdf");
        let mut pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        pdf.write_manifest_as_embedded_file(vec![10u8, 20u8])
            .unwrap();

        assert!(pdf.has_c2pa_manifest());
    }

    #[test]
    fn test_save_to() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        assert!(!pdf.has_c2pa_manifest());

        pdf.write_manifest_as_annotation(vec![10u8]).unwrap();
        assert!(pdf.has_c2pa_manifest());

        let mut saved_bytes = vec![];
        pdf.save_to(&mut saved_bytes).unwrap();

        // Round-trip through this backend...
        let saved_pdf = PdfOxideDoc::from_bytes(&saved_bytes).unwrap();
        assert!(saved_pdf.has_c2pa_manifest());
        assert_eq!(
            saved_pdf.read_manifest_bytes().unwrap(),
            Some(vec![[10u8].as_slice()])
        );

        // ...and through the lopdf backend, as a cross-parser sanity check that the hand-rolled
        // serializer produced a well-formed PDF, not just one `pdf_oxide` happens to tolerate.
        let lopdf_pdf = super::super::pdf::Pdf::from_bytes(&saved_bytes).unwrap();
        assert!(lopdf_pdf.has_c2pa_manifest());
    }

    #[test]
    fn test_reads_manifest_bytes_for_embedded_files_manifest() {
        let bytes = include_bytes!("../../tests/fixtures/express.pdf");
        let mut pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
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

    #[test]
    fn test_reads_manifest_bytes_for_annotation_manifest() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
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

    #[test]
    fn test_remove_manifest_bytes_from_file_without_c2pa_returns_error() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut pdf = PdfOxideDoc::from_bytes(bytes).unwrap();

        assert!(matches!(pdf.remove_manifest_bytes(), Err(Error::NoManifest)));
    }

    #[test]
    fn test_remove_manifest_from_file_with_annotation_based_manifest() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        let manifest_bytes = vec![0u8, 1u8, 1u8, 2u8, 3u8];
        pdf.write_manifest_as_annotation(manifest_bytes).unwrap();

        assert!(pdf.has_c2pa_manifest());
        assert!(pdf.remove_manifest_bytes().is_ok());
        assert!(!pdf.has_c2pa_manifest());
    }

    #[test]
    fn test_remove_manifest_from_file_with_embedded_file_based_manifest() {
        let bytes = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut pdf = PdfOxideDoc::from_bytes(bytes).unwrap();
        let manifest_bytes = vec![0u8, 1u8, 1u8, 2u8, 3u8];

        pdf.write_manifest_as_embedded_file(manifest_bytes)
            .unwrap();

        assert!(pdf.has_c2pa_manifest());
        assert!(pdf.remove_manifest_bytes().is_ok());
        assert!(!pdf.has_c2pa_manifest());
    }
}
