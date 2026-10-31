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

//! Standalone TTML (`application/ttml+xml`) asset handler, per "Embedding manifests into
//! TTML" in the C2PA 2.5 specification.
//!
//! The Manifest Store is the Base64-encoded content of a `c2pa:manifest` element at
//! `/tt:tt/tt:head/tt:metadata/c2pa:manifest`, with `xmlns:c2pa` declared on the root
//! element. The `c2pa.hash.data` exclusion covers that element, from the opening
//! `<c2pa:manifest>` tag through the closing tag. The document is otherwise kept byte for
//! byte: `tt:head` and `tt:metadata` are added only when missing.

use quick_xml::{
    events::{BytesStart, Event},
    name::ResolveResult,
    NsReader,
};

use crate::{
    asset_handlers::text_common,
    asset_io::{AssetIO, C2paReader, C2paWriter, ObjectLocations, ReadSeek, ReadWriteSeek},
    crypto::base64,
    error::{Error, Result},
};

static SUPPORTED_TYPES: [&str; 3] = ["ttml", "dfxp", "application/ttml+xml"];

const TTML_NS: &[u8] = b"http://www.w3.org/ns/ttml";
const C2PA_NS: &str = "http://c2pa.org/manifest";
const C2PA_NS_DECL: &str = "xmlns:c2pa";
const MANIFEST: &str = "c2pa:manifest";

/// Placeholder used to lay out the exclusion before a manifest exists.
const PLACEHOLDER_STORE: &[u8] = b"placeholder manifest";

/// The byte span of one element: `[start, open_end)` is the start tag and
/// `[close_start, end)` the end tag. An empty-element tag (`<x/>`) has
/// `open_end == close_start == end`.
#[derive(Clone, Copy)]
struct Span {
    start: usize,
    open_end: usize,
    close_start: usize,
    end: usize,
    empty: bool,
}

struct Element {
    span: Span,
    /// The qualified-name prefix (`tt` for `<tt:head>`), if any.
    prefix: Option<String>,
}

/// Where the parts of a TTML document that matter for embedding are.
struct Layout {
    root: Element,
    /// Whether the root already declares `xmlns:c2pa="http://c2pa.org/manifest"`.
    root_declares_c2pa: bool,
    head: Option<Element>,
    /// The first `tt:metadata` child of `tt:head`.
    metadata: Option<Element>,
    /// Every `c2pa:manifest` child of a `tt:metadata` child of `tt:head`.
    manifests: Vec<Span>,
}

#[derive(Clone, Copy, PartialEq)]
enum Node {
    Root,
    Head,
    Metadata,
    Manifest,
    Other,
}

fn invalid(msg: &str) -> Error {
    Error::InvalidAsset(format!("TTML: {msg}"))
}

fn prefix_of(e: &BytesStart) -> Option<String> {
    e.name()
        .prefix()
        .map(|p| String::from_utf8_lossy(p.into_inner()).into_owned())
}

/// Checks the root's `xmlns:c2pa` declaration: `Ok(true)` if it binds the C2PA namespace,
/// `Ok(false)` if absent, and an error if the `c2pa` prefix is bound to something else.
fn root_c2pa_declaration(root: &BytesStart) -> Result<bool> {
    for attr in root.attributes().flatten() {
        if attr.key.as_ref() == C2PA_NS_DECL.as_bytes() {
            return if attr.value.as_ref() == C2PA_NS.as_bytes() {
                Ok(true)
            } else {
                Err(invalid("the c2pa prefix is bound to another namespace"))
            };
        }
    }
    Ok(false)
}

fn parse(text: &str) -> Result<Layout> {
    let mut reader = NsReader::from_str(text);
    let mut path: Vec<(Node, usize)> = Vec::new(); // node, index into `open`
    let mut open: Vec<Span> = Vec::new();
    let mut root: Option<Element> = None;
    let mut root_declares_c2pa = false;
    let mut head: Option<Element> = None;
    let mut metadata: Option<Element> = None;
    let mut manifests = Vec::new();

    loop {
        let before = reader.buffer_position() as usize;
        let (ns, event) = {
            let (ns, event) = reader
                .read_resolved_event()
                .map_err(|_| invalid("not well-formed XML"))?;
            let ns = match ns {
                ResolveResult::Bound(ns) => Some(ns.into_inner().to_vec()),
                _ => None,
            };
            (ns, event)
        };
        let after = reader.buffer_position() as usize;
        let in_ns = |want: &[u8]| ns.as_deref() == Some(want);

        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let empty = matches!(event, Event::Empty(_));
                let local = e.local_name();
                let parent = path.last().map(|(n, _)| *n);
                let node = match (parent, local.as_ref()) {
                    (None, b"tt") if in_ns(TTML_NS) => Node::Root,
                    (None, _) => return Err(Error::UnsupportedType),
                    (Some(Node::Root), b"head") if in_ns(TTML_NS) => Node::Head,
                    (Some(Node::Head), b"metadata") if in_ns(TTML_NS) => Node::Metadata,
                    (Some(Node::Metadata), b"manifest") if in_ns(C2PA_NS.as_bytes()) => {
                        Node::Manifest
                    }
                    _ => Node::Other,
                };
                let span = Span {
                    start: before,
                    open_end: after,
                    close_start: after,
                    end: after,
                    empty,
                };
                if node == Node::Root {
                    root_declares_c2pa = root_c2pa_declaration(e)?;
                }
                if empty {
                    match node {
                        Node::Root => return Err(invalid("the tt element is empty")),
                        Node::Head if head.is_none() => {
                            head = Some(Element {
                                span,
                                prefix: prefix_of(e),
                            })
                        }
                        Node::Metadata if metadata.is_none() => {
                            metadata = Some(Element {
                                span,
                                prefix: prefix_of(e),
                            })
                        }
                        Node::Manifest => manifests.push(span),
                        _ => {}
                    }
                } else {
                    let prefix = prefix_of(e);
                    match node {
                        Node::Root => root = Some(Element { span, prefix }),
                        Node::Head if head.is_none() => head = Some(Element { span, prefix }),
                        Node::Metadata if metadata.is_none() => {
                            metadata = Some(Element { span, prefix })
                        }
                        _ => {}
                    }
                    open.push(span);
                    path.push((node, open.len() - 1));
                }
            }
            Event::End(_) => {
                let (node, index) = path.pop().ok_or_else(|| invalid("unbalanced end tag"))?;
                let span = Span {
                    close_start: before,
                    end: after,
                    ..open[index]
                };
                let fix = |el: &mut Option<Element>| {
                    if let Some(el) = el.as_mut().filter(|el| el.span.start == span.start) {
                        el.span = span;
                    }
                };
                match node {
                    Node::Root => fix(&mut root),
                    Node::Head => fix(&mut head),
                    Node::Metadata => fix(&mut metadata),
                    Node::Manifest => manifests.push(span),
                    Node::Other => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    let root = root.ok_or(Error::UnsupportedType)?;
    Ok(Layout {
        root,
        root_declares_c2pa,
        head,
        metadata,
        manifests,
    })
}

fn qualified(prefix: &Option<String>, local: &str) -> String {
    match prefix {
        Some(p) => format!("{p}:{local}"),
        None => local.to_string(),
    }
}

fn manifest_element(store_bytes: &[u8]) -> String {
    format!("<{MANIFEST}>{}</{MANIFEST}>", base64::encode(store_bytes))
}

/// Returns `text` with the manifest element for `store_bytes` in place, replacing an
/// existing one, or inserting it (and any missing `tt:metadata` / `tt:head`) otherwise.
fn embed(text: &str, store_bytes: &[u8]) -> Result<String> {
    let layout = parse(text)?;
    let element = manifest_element(store_bytes);

    // Each edit is (start, end, replacement) on the original text; applied back to front.
    let mut edits: Vec<(usize, usize, String)> = Vec::new();

    match layout.manifests.as_slice() {
        [existing] => edits.push((existing.start, existing.end, element)),
        [] => {
            if let Some(md) = &layout.metadata {
                if md.span.empty {
                    let name = qualified(&md.prefix, "metadata");
                    edits.push((
                        md.span.start,
                        md.span.end,
                        format!("<{name}>{element}</{name}>"),
                    ));
                } else {
                    edits.push((md.span.close_start, md.span.close_start, element));
                }
            } else {
                let metadata = qualified(
                    &layout
                        .head
                        .as_ref()
                        .map_or(layout.root.prefix.clone(), |h| h.prefix.clone()),
                    "metadata",
                );
                let block = format!("<{metadata}>{element}</{metadata}>");
                match &layout.head {
                    Some(head) if head.span.empty => {
                        let name = qualified(&head.prefix, "head");
                        edits.push((
                            head.span.start,
                            head.span.end,
                            format!("<{name}>{block}</{name}>"),
                        ));
                    }
                    // `tt:metadata` comes first in `tt:head` (TTML2 8.1.1).
                    Some(head) => edits.push((head.span.open_end, head.span.open_end, block)),
                    None => {
                        let name = qualified(&layout.root.prefix, "head");
                        let at = layout.root.span.open_end;
                        edits.push((at, at, format!("<{name}>{block}</{name}>")));
                    }
                }
            }
        }
        _ => return Err(invalid("more than one c2pa:manifest element")),
    }

    if !layout.root_declares_c2pa {
        let open_end = layout.root.span.open_end;
        // The start tag ends with `>`; declare the namespace just before it.
        let at = open_end - 1;
        edits.push((at, at, format!(" {C2PA_NS_DECL}=\"{C2PA_NS}\"")));
    }

    edits.sort_by_key(|(start, _, _)| std::cmp::Reverse(*start));
    let mut out = text.to_string();
    for (start, end, replacement) in edits {
        out.replace_range(start..end, &replacement);
    }
    Ok(out)
}

/// The single manifest element's span, or `None` if there is none or more than one.
fn single_manifest(layout: &Layout) -> Option<Span> {
    match layout.manifests.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

pub struct TtmlIO {}

impl C2paReader for TtmlIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let text = text_common::read_text_stream(input_stream)?;
        let layout = parse(&text)?;
        // More than one manifest element is treated as no manifest.
        let span = single_manifest(&layout).ok_or(Error::JumbfNotFound)?;
        if span.empty {
            return Err(Error::JumbfNotFound);
        }
        let encoded = text[span.open_end..span.close_start].trim();
        let bytes = base64::decode(encoded).map_err(|_| invalid("manifest is not Base64"))?;
        if bytes.is_empty() {
            return Err(Error::JumbfNotFound);
        }
        Ok(bytes)
    }

    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for TtmlIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let text = text_common::read_text_stream(input_stream)?;
        let out = embed(&text, store_bytes)?;
        output_stream.rewind()?;
        output_stream.write_all(out.as_bytes())?;
        Ok(())
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let text = text_common::read_text_stream(input_stream)?;
        let layout = parse(&text)?;
        let (full_len, span) = match single_manifest(&layout) {
            Some(span) => (text.len(), span),
            None if layout.manifests.is_empty() => {
                // No manifest yet: lay out the exclusion with a placeholder.
                let with_manifest = embed(&text, PLACEHOLDER_STORE)?;
                let span = single_manifest(&parse(&with_manifest)?).ok_or(Error::EmbeddingError)?;
                (with_manifest.len(), span)
            }
            None => return Err(invalid("more than one c2pa:manifest element")),
        };
        Ok(text_common::hash_positions(
            full_len,
            span.start,
            span.end - span.start,
        ))
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        let text = text_common::read_text_stream(input_stream)?;
        let layout = parse(&text)?;
        let mut out = text.clone();
        for span in layout.manifests.iter().rev() {
            out.replace_range(span.start..span.end, "");
        }
        output_stream.rewind()?;
        output_stream.write_all(out.as_bytes())?;
        Ok(())
    }
}

impl AssetIO for TtmlIO {
    fn new(_asset_type: &str) -> Self {
        TtmlIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(TtmlIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(TtmlIO::new(asset_type)))
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::asset_io::ObjectType;

    const DOC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<tt:tt xml:lang="en" xmlns:tt="http://www.w3.org/ns/ttml">
  <tt:head>
    <tt:metadata>
      <tt:title>Example</tt:title>
    </tt:metadata>
  </tt:head>
  <tt:body>
    <tt:div>
      <tt:p begin="00:00:01.000" end="00:00:04.000">Example subtitle text.</tt:p>
    </tt:div>
  </tt:body>
</tt:tt>
"#;

    fn write(source: &str, store: &[u8]) -> String {
        let mut input = Cursor::new(source.as_bytes().to_vec());
        let mut output = Cursor::new(Vec::new());
        TtmlIO {}
            .write_c2pa(&mut input, &mut output, store)
            .unwrap();
        String::from_utf8(output.into_inner()).unwrap()
    }

    fn read(text: &str) -> Result<Vec<u8>> {
        TtmlIO {}.read_c2pa(&mut Cursor::new(text.as_bytes().to_vec()))
    }

    fn c2pa_location(text: &str) -> ObjectLocations {
        let locations = TtmlIO {}
            .get_object_locations(&mut Cursor::new(text.as_bytes().to_vec()))
            .unwrap();
        locations
            .into_iter()
            .find(|l| l.htype == ObjectType::C2pa)
            .unwrap()
    }

    #[test]
    fn embeds_in_existing_metadata_and_round_trips() {
        let out = write(DOC, b"store bytes");
        assert!(out.contains(r#"<tt:tt xml:lang="en" xmlns:tt="http://www.w3.org/ns/ttml" xmlns:c2pa="http://c2pa.org/manifest">"#));
        assert!(out.contains("<tt:title>Example</tt:title>\n    <c2pa:manifest>"));
        assert_eq!(read(&out).unwrap(), b"store bytes");
    }

    #[test]
    fn exclusion_is_exactly_the_manifest_element() {
        let out = write(DOC, b"store bytes");
        let loc = c2pa_location(&out);
        let excluded = &out[loc.offset as usize..(loc.offset + loc.length) as usize];
        assert!(excluded.starts_with("<c2pa:manifest>"));
        assert!(excluded.ends_with("</c2pa:manifest>"));
        // Everything else is the original document plus the namespace declaration.
        let rest = format!(
            "{}{}",
            &out[..loc.offset as usize],
            &out[(loc.offset + loc.length) as usize..]
        );
        assert_eq!(
            rest.replace(r#" xmlns:c2pa="http://c2pa.org/manifest""#, ""),
            DOC
        );
    }

    #[test]
    fn placeholder_layout_matches_the_written_layout() {
        let store = vec![7u8; PLACEHOLDER_STORE.len()];
        let before = c2pa_location(DOC);
        let after = c2pa_location(&write(DOC, &store));
        assert_eq!((before.offset, before.length), (after.offset, after.length));
    }

    #[test]
    fn replaces_in_place_and_keeps_one_namespace_declaration() {
        let first = write(DOC, b"AAAA");
        let offset = c2pa_location(&first).offset;
        let second = write(&first, b"BBBB");
        assert_eq!(c2pa_location(&second).offset, offset);
        assert_eq!(second.matches(C2PA_NS_DECL).count(), 1);
        assert_eq!(read(&second).unwrap(), b"BBBB");
    }

    #[test]
    fn adds_missing_head_and_metadata_with_the_document_prefix() {
        let doc = r#"<tt xmlns="http://www.w3.org/ns/ttml"><body><div/></body></tt>"#;
        let out = write(doc, b"store");
        assert!(out.starts_with(r#"<tt xmlns="http://www.w3.org/ns/ttml" xmlns:c2pa="http://c2pa.org/manifest"><head><metadata><c2pa:manifest>"#));
        assert_eq!(read(&out).unwrap(), b"store");

        let doc = r#"<tt:tt xmlns:tt="http://www.w3.org/ns/ttml"><tt:head><tt:styling/></tt:head><tt:body/></tt:tt>"#;
        let out = write(doc, b"store");
        assert!(out.contains("<tt:head><tt:metadata><c2pa:manifest>"));
        assert_eq!(read(&out).unwrap(), b"store");

        let doc = r#"<tt:tt xmlns:tt="http://www.w3.org/ns/ttml"><tt:head><tt:metadata/></tt:head><tt:body/></tt:tt>"#;
        let out = write(doc, b"store");
        assert!(out.contains("<tt:metadata><c2pa:manifest>"));
        assert_eq!(read(&out).unwrap(), b"store");
    }

    #[test]
    fn manifest_outside_head_metadata_is_not_read() {
        let manifest = manifest_element(b"store");
        let doc = format!(
            r#"<tt xmlns="http://www.w3.org/ns/ttml" xmlns:c2pa="http://c2pa.org/manifest"><body><metadata>{manifest}</metadata></body></tt>"#
        );
        assert!(matches!(read(&doc), Err(Error::JumbfNotFound)));
    }

    #[test]
    fn two_manifests_are_treated_as_no_manifest() {
        let out = write(DOC, b"store");
        let element = manifest_element(b"other");
        let doubled = out.replacen("</tt:metadata>", &format!("{element}</tt:metadata>"), 1);
        assert!(matches!(read(&doubled), Err(Error::JumbfNotFound)));
        let mut output = Cursor::new(Vec::new());
        assert!(TtmlIO {}
            .write_c2pa(&mut Cursor::new(doubled.into_bytes()), &mut output, b"x")
            .is_err());
    }

    #[test]
    fn non_ttml_xml_is_unsupported() {
        let mut output = Cursor::new(Vec::new());
        assert!(matches!(
            TtmlIO {}.write_c2pa(
                &mut Cursor::new(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>".to_vec()),
                &mut output,
                b"x"
            ),
            Err(Error::UnsupportedType)
        ));
    }

    #[test]
    fn remove_restores_the_document() {
        let out = write(DOC, b"store");
        let mut output = Cursor::new(Vec::new());
        TtmlIO {}
            .remove_c2pa(&mut Cursor::new(out.into_bytes()), &mut output)
            .unwrap();
        let removed = String::from_utf8(output.into_inner()).unwrap();
        assert!(matches!(read(&removed), Err(Error::JumbfNotFound)));
        assert_eq!(
            removed.replace(r#" xmlns:c2pa="http://c2pa.org/manifest""#, ""),
            DOC
        );
    }
}
