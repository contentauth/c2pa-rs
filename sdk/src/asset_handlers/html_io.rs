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

//! HTML asset handler (C2PA spec A.7): associates a Manifest Store with a document through
//! an inline `<script type="application/c2pa">` element (Base64 manifest, excluded from the
//! data hash) or an external `<link rel="c2pa-manifest">` element (nothing excluded) in the
//! document `head`. A document with more than one manifest element in its `head` is treated
//! as having no manifest.

use std::io::SeekFrom;

use crate::{
    asset_io::{
        AssetIO, AssetPatch, C2paReader, C2paWriter, ObjectLocations, ObjectType, ReadSeek,
        ReadWriteSeek, RemoteManifestUrl,
    },
    crypto::base64,
    error::{Error, Result},
    utils::io_utils::{stream_len, ReaderUtils},
};

const MANIFEST_MEDIA_TYPE: &str = "application/c2pa";
const MANIFEST_LINK_REL: &str = "c2pa-manifest";

const SUPPORTED_TYPES: [&str; 3] = ["html", "htm", "text/html"];

/// Used only to size a script element before the real manifest is known, so
/// [`get_object_locations`](C2paWriter::get_object_locations) can report an exclusion range
/// on a document that does not carry one yet.
const PLACEHOLDER_STORE: &[u8] = b"placeholder manifest";

/// A C2PA manifest element in the document `head`. `start..end` covers the whole element,
/// from the opening `<` through the closing `>`.
#[derive(Debug, Clone, PartialEq)]
enum ManifestElement {
    Script {
        start: usize,
        end: usize,
        content: (usize, usize),
    },
    Link {
        start: usize,
        end: usize,
        href: String,
    },
}

impl ManifestElement {
    fn range(&self) -> (usize, usize) {
        match self {
            ManifestElement::Script { start, end, .. } | ManifestElement::Link { start, end, .. } => {
                (*start, *end)
            }
        }
    }
}

fn find_ci(content: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= content.len() || needle.len() > content.len() - from {
        return None;
    }
    content[from..]
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
        .map(|p| p + from)
}

/// True when `content[pos..]` starts the tag `name` (e.g. `<head`), not a longer name such as
/// `<header`.
fn is_tag(content: &[u8], pos: usize, name: &[u8]) -> bool {
    let end = pos + name.len();
    end <= content.len()
        && content[pos..end].eq_ignore_ascii_case(name)
        && content
            .get(end)
            .is_none_or(|b| b.is_ascii_whitespace() || *b == b'>' || *b == b'/')
}

fn find_tag(content: &[u8], name: &[u8], from: usize) -> Option<usize> {
    let mut pos = from;
    while let Some(p) = find_ci(content, name, pos) {
        if is_tag(content, p, name) {
            return Some(p);
        }
        pos = p + 1;
    }
    None
}

/// Returns the offset just past the `>` that closes the tag starting at `start`, ignoring any
/// `>` inside quoted attribute values.
fn tag_end(content: &[u8], start: usize) -> Option<usize> {
    let mut quote = None;
    for (i, &b) in content.iter().enumerate().skip(start) {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(i + 1),
            None => {}
        }
    }
    None
}

/// Parses the attributes of a start tag into (lowercase name, value) pairs.
fn parse_attributes(tag: &[u8]) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    // skip `<` and the tag name
    let mut i = 1;
    while i < tag.len() && !tag[i].is_ascii_whitespace() && tag[i] != b'>' && tag[i] != b'/' {
        i += 1;
    }

    loop {
        while i < tag.len() && (tag[i].is_ascii_whitespace() || tag[i] == b'/') {
            i += 1;
        }
        if i >= tag.len() || tag[i] == b'>' {
            break;
        }

        let name_start = i;
        while i < tag.len() && !tag[i].is_ascii_whitespace() && !matches!(tag[i], b'=' | b'>' | b'/')
        {
            i += 1;
        }
        let name = String::from_utf8_lossy(&tag[name_start..i]).to_ascii_lowercase();

        while i < tag.len() && tag[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < tag.len() && tag[i] == b'=' {
            i += 1;
            while i < tag.len() && tag[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < tag.len() && (tag[i] == b'"' || tag[i] == b'\'') {
                let quote = tag[i];
                let value_start = i + 1;
                i = value_start;
                while i < tag.len() && tag[i] != quote {
                    i += 1;
                }
                value = String::from_utf8_lossy(&tag[value_start..i.min(tag.len())]).into_owned();
                i += 1;
            } else {
                let value_start = i;
                while i < tag.len() && !tag[i].is_ascii_whitespace() && tag[i] != b'>' {
                    i += 1;
                }
                value = String::from_utf8_lossy(&tag[value_start..i]).into_owned();
            }
        }
        attrs.push((name, value));
    }

    attrs
}

fn attribute<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// Decodes the character references that can appear in a URL attribute value.
fn unescape_attribute(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Returns the byte range between the end of the `<head>` start tag and `</head>`.
fn head_region(content: &[u8]) -> Option<(usize, usize)> {
    let head = find_tag(content, b"<head", 0)?;
    let body_start = tag_end(content, head)?;
    let body_end = find_tag(content, b"</head", body_start).unwrap_or(content.len());
    Some((body_start, body_end))
}

/// Finds every C2PA manifest element in the document `head`. A matching element outside the
/// `head` does not form an association and is ignored (A.7.1).
fn find_manifest_elements(content: &[u8]) -> Vec<ManifestElement> {
    let mut elements = Vec::new();
    let Some((head_start, head_end)) = head_region(content) else {
        return elements;
    };

    let mut pos = head_start;
    while pos < head_end {
        let Some(lt) = content[pos..head_end].iter().position(|b| *b == b'<') else {
            break;
        };
        let start = pos + lt;

        if content[start..].starts_with(b"<!--") {
            pos = find_ci(content, b"-->", start + 4).map_or(head_end, |p| p + 3);
            continue;
        }

        let Some(end_of_start_tag) = tag_end(content, start) else {
            break;
        };

        if is_tag(content, start, b"<script") {
            // script content is raw text, so skip straight to the closing tag
            let close = find_tag(content, b"</script", end_of_start_tag);
            let end = close.and_then(|c| tag_end(content, c)).unwrap_or(head_end);
            let attrs = parse_attributes(&content[start..end_of_start_tag]);
            let is_manifest = attribute(&attrs, "type")
                .is_some_and(|t| t.trim().eq_ignore_ascii_case(MANIFEST_MEDIA_TYPE));
            if is_manifest {
                elements.push(ManifestElement::Script {
                    start,
                    end,
                    content: (end_of_start_tag, close.unwrap_or(end)),
                });
            }
            pos = end;
        } else if is_tag(content, start, b"<link") {
            let attrs = parse_attributes(&content[start..end_of_start_tag]);
            // the validator matches on the rel attribute alone (A.7.1.2)
            let is_manifest = attribute(&attrs, "rel").is_some_and(|rel| {
                rel.split_ascii_whitespace()
                    .any(|r| r.eq_ignore_ascii_case(MANIFEST_LINK_REL))
            });
            if is_manifest {
                elements.push(ManifestElement::Link {
                    start,
                    end: end_of_start_tag,
                    href: unescape_attribute(attribute(&attrs, "href").unwrap_or_default()),
                });
            }
            pos = end_of_start_tag;
        } else {
            pos = end_of_start_tag;
        }
    }

    elements
}

/// The document's single manifest element. More than one in the `head` is treated as no
/// manifest (A.7.1).
fn manifest_element(content: &[u8]) -> Option<ManifestElement> {
    let mut elements = find_manifest_elements(content);
    if elements.len() == 1 {
        elements.pop()
    } else {
        None
    }
}

fn read_document(mut reader: &mut dyn ReadSeek) -> Result<Vec<u8>> {
    reader.rewind()?;
    let len = stream_len(reader)?;
    reader.read_to_vec(len)
}

fn script_element(store_bytes: &[u8]) -> String {
    format!(
        "<script type=\"{MANIFEST_MEDIA_TYPE}\">{}</script>",
        base64::encode(store_bytes)
    )
}

fn link_element(url: &str) -> String {
    let href = url.replace('&', "&amp;").replace('"', "&quot;");
    format!("<link rel=\"{MANIFEST_LINK_REL}\" href=\"{href}\" type=\"{MANIFEST_MEDIA_TYPE}\">")
}

/// Removes every manifest element from the `head`.
fn strip_manifest_elements(content: &[u8]) -> Vec<u8> {
    let mut out = content.to_vec();
    // remove from the back so earlier offsets stay valid
    for element in find_manifest_elements(content).iter().rev() {
        let (start, end) = element.range();
        out.drain(start..end);
    }
    out
}

/// Inserts `element` at the end of the `head`, creating a `head` when the document has none.
fn insert_element(content: &[u8], element: &str) -> Vec<u8> {
    let (at, insert) = if let Some((_, head_end)) = head_region(content) {
        (head_end, element.to_string())
    } else {
        // no head: open one right after the <html> start tag (or the doctype)
        let after = find_tag(content, b"<html", 0)
            .or_else(|| find_tag(content, b"<!doctype", 0))
            .and_then(|p| tag_end(content, p))
            .unwrap_or(0);
        (after, format!("<head>{element}</head>"))
    };

    let mut out = Vec::with_capacity(content.len() + insert.len());
    out.extend_from_slice(&content[..at]);
    out.extend_from_slice(insert.as_bytes());
    out.extend_from_slice(&content[at..]);
    out
}

/// Replaces every existing manifest element with `element`. A single existing element is
/// replaced in place, which keeps the offsets of the rest of the document.
fn replace_manifest_elements(content: &[u8], element: &str) -> Vec<u8> {
    let elements = find_manifest_elements(content);
    if let [existing] = elements.as_slice() {
        let (start, end) = existing.range();
        return [&content[..start], element.as_bytes(), &content[end..]].concat();
    }
    insert_element(&strip_manifest_elements(content), element)
}

/// `c2pa.hash.data` layout: excluded script element, plus content before/after.
fn hash_positions(full_len: usize, start: usize, end: usize) -> Vec<ObjectLocations> {
    vec![
        ObjectLocations {
            offset: start as u64,
            length: (end - start) as u64,
            htype: ObjectType::C2pa,
        },
        ObjectLocations {
            offset: 0,
            length: start as u64,
            htype: ObjectType::Other,
        },
        ObjectLocations {
            offset: end as u64,
            length: full_len.saturating_sub(end) as u64,
            htype: ObjectType::Other,
        },
    ]
}

pub struct HtmlIO {}

impl C2paReader for HtmlIO {
    fn read_c2pa(&self, reader: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let content = read_document(reader)?;
        match manifest_element(&content) {
            Some(ManifestElement::Script {
                content: (from, to),
                ..
            }) => {
                // whitespace around the Base64 text is stripped before decoding (A.7.1.1)
                let b64 = String::from_utf8_lossy(&content[from..to]);
                base64::decode(b64.trim())
                    .map_err(|_| Error::InvalidAsset("invalid Base64 in HTML manifest".to_string()))
            }
            // an external manifest is referenced, not embedded
            Some(ManifestElement::Link { .. }) | None => Err(Error::JumbfNotFound),
        }
    }

    fn read_xmp(&self, _asset_reader: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for HtmlIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let content = read_document(input_stream)?;
        let out = replace_manifest_elements(&content, &script_element(store_bytes));
        output_stream.rewind()?;
        output_stream.write_all(&out)?;
        Ok(())
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let content = read_document(input_stream)?;

        match manifest_element(&content) {
            Some(ManifestElement::Script { start, end, .. }) => {
                Ok(hash_positions(content.len(), start, end))
            }
            // with a link element the whole document is hashed (A.7.1.3)
            Some(ManifestElement::Link { .. }) => Ok(vec![ObjectLocations {
                offset: 0,
                length: content.len() as u64,
                htype: ObjectType::Other,
            }]),
            None => {
                // No manifest yet: report where the script element will be embedded, sized
                // with a placeholder, so the data hash reserves room for the exclusion.
                let with_script = replace_manifest_elements(&content, &script_element(PLACEHOLDER_STORE));
                match manifest_element(&with_script) {
                    Some(ManifestElement::Script { start, end, .. }) => {
                        Ok(hash_positions(with_script.len(), start, end))
                    }
                    _ => Err(Error::EmbeddingError),
                }
            }
        }
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        let content = read_document(input_stream)?;
        output_stream.rewind()?;
        output_stream.write_all(&strip_manifest_elements(&content))?;
        Ok(())
    }
}

impl AssetPatch for HtmlIO {
    fn patch_c2pa(&self, stream: &mut dyn ReadWriteSeek, store_bytes: &[u8]) -> Result<()> {
        let content = read_document(stream)?;
        let Some(ManifestElement::Script { start, end, .. }) = manifest_element(&content) else {
            return Err(Error::JumbfNotFound);
        };

        let new_element = script_element(store_bytes);
        if new_element.len() != end - start {
            return Err(Error::InvalidAsset(
                "patch_c2pa size mismatch".to_string(),
            ));
        }
        stream.seek(SeekFrom::Start(start as u64))?;
        stream.write_all(new_element.as_bytes())?;
        Ok(())
    }
}

impl RemoteManifestUrl for HtmlIO {
    fn write_remote_manifest_url(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        remote_manifest_url: &str,
    ) -> Result<()> {
        let content = read_document(input_stream)?;
        let out = replace_manifest_elements(&content, &link_element(remote_manifest_url));
        output_stream.rewind()?;
        output_stream.write_all(&out)?;
        Ok(())
    }

    fn read_manifest_url(&self, input_stream: &mut dyn ReadSeek) -> Option<String> {
        let content = read_document(input_stream).ok()?;
        match manifest_element(&content)? {
            ManifestElement::Link { href, .. } if !href.is_empty() => Some(href),
            _ => None,
        }
    }

    fn remove_remote_manifest_url(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        let content = read_document(input_stream)?;
        let mut out = content.clone();
        for element in find_manifest_elements(&content).iter().rev() {
            if let ManifestElement::Link { start, end, .. } = element {
                out.drain(*start..*end);
            }
        }
        output_stream.rewind()?;
        output_stream.write_all(&out)?;
        Ok(())
    }
}

impl AssetIO for HtmlIO {
    fn new(_asset_type: &str) -> Self {
        HtmlIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(HtmlIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(HtmlIO::new(asset_type)))
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn remote_manifest_url_ref(&self) -> Option<&dyn RemoteManifestUrl> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    const DOC: &str = "<!DOCTYPE html>\n<html>\n<head>\n<title>t</title>\n</head>\n<body><p>hi</p></body>\n</html>\n";

    fn embed(content: &str, store: &[u8]) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        HtmlIO::new("html")
            .write_c2pa(&mut Cursor::new(content.as_bytes().to_vec()), &mut out, store)
            .unwrap();
        out.into_inner()
    }

    fn read_back(doc: &[u8]) -> Result<Vec<u8>> {
        HtmlIO::new("html").read_c2pa(&mut Cursor::new(doc.to_vec()))
    }

    fn link(doc: &str, url: &str) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        HtmlIO::new("html")
            .write_remote_manifest_url(&mut Cursor::new(doc.as_bytes().to_vec()), &mut out, url)
            .unwrap();
        out.into_inner()
    }

    #[test]
    fn script_round_trips_in_head() {
        let out = embed(DOC, b"manifest");
        let text = String::from_utf8(out.clone()).unwrap();
        assert!(text.find("application/c2pa").unwrap() < text.find("</head>").unwrap());
        assert_eq!(read_back(&out).unwrap(), b"manifest");
    }

    #[test]
    fn replaces_existing_script() {
        let once = String::from_utf8(embed(DOC, b"old")).unwrap();
        let twice = embed(&once, b"new");
        assert_eq!(String::from_utf8(twice.clone()).unwrap().matches("application/c2pa").count(), 1);
        assert_eq!(read_back(&twice).unwrap(), b"new");
    }

    #[test]
    fn script_whitespace_is_trimmed() {
        let doc = format!(
            "<html><head><script type=\"application/c2pa\">\n    {}\n  </script></head></html>",
            base64::encode(b"data")
        );
        assert_eq!(read_back(doc.as_bytes()).unwrap(), b"data");
    }

    #[test]
    fn creates_head_when_missing() {
        let out = String::from_utf8(embed("<html><body>x</body></html>", b"m")).unwrap();
        assert!(out.starts_with("<html><head><script type=\"application/c2pa\">"));
    }

    #[test]
    fn object_locations_exclude_script_element() {
        let out = embed(DOC, b"manifest");
        let text = String::from_utf8(out.clone()).unwrap();
        let start = text.find("<script").unwrap() as u64;
        let end = (text.find("</script>").unwrap() + "</script>".len()) as u64;

        let locations = HtmlIO::new("html")
            .get_object_locations(&mut Cursor::new(out))
            .unwrap();
        let c2pa = locations.iter().find(|p| p.htype == ObjectType::C2pa).unwrap();
        assert_eq!((c2pa.offset, c2pa.length), (start, end - start));
    }

    #[test]
    fn object_locations_reserve_room_before_embedding() {
        let locations = HtmlIO::new("html")
            .get_object_locations(&mut Cursor::new(DOC.as_bytes().to_vec()))
            .unwrap();
        let c2pa = locations.iter().find(|p| p.htype == ObjectType::C2pa).unwrap();
        assert_eq!(c2pa.offset, DOC.find("</head>").unwrap() as u64);
        assert!(c2pa.length > 0);
    }

    #[test]
    fn link_element_is_hashed_and_readable_as_url() {
        let out = link(DOC, "https://example.com/a.c2pa?x=1&y=2");
        let text = String::from_utf8(out.clone()).unwrap();
        assert!(text.contains("<link rel=\"c2pa-manifest\" href=\"https://example.com/a.c2pa?x=1&amp;y=2\""));

        let locations = HtmlIO::new("html")
            .get_object_locations(&mut Cursor::new(out.clone()))
            .unwrap();
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].htype, ObjectType::Other);
        assert_eq!(locations[0].length, out.len() as u64);

        assert!(matches!(read_back(&out), Err(Error::JumbfNotFound)));
        assert_eq!(
            HtmlIO::new("html").read_manifest_url(&mut Cursor::new(out)),
            Some("https://example.com/a.c2pa?x=1&y=2".to_string())
        );
    }

    #[test]
    fn remove_remote_manifest_url_strips_link() {
        let linked = link(DOC, "https://example.com/a.c2pa");
        let mut out = Cursor::new(Vec::new());
        HtmlIO::new("html")
            .remove_remote_manifest_url(&mut Cursor::new(linked), &mut out)
            .unwrap();
        assert_eq!(out.into_inner(), DOC.as_bytes());
    }

    #[test]
    fn multiple_manifest_elements_treated_as_no_manifest() {
        for doc in [
            "<html><head><script type=\"application/c2pa\">YQ==</script><script type=\"application/c2pa\">Yg==</script></head></html>",
            "<html><head><script type=\"application/c2pa\">YQ==</script><link rel=\"c2pa-manifest\" href=\"https://example.com/a.c2pa\"></head></html>",
        ] {
            assert!(matches!(read_back(doc.as_bytes()), Err(Error::JumbfNotFound)));
            // writing replaces them all with a single script
            let out = String::from_utf8(embed(doc, b"one")).unwrap();
            assert_eq!(find_manifest_elements(out.as_bytes()).len(), 1);
        }
    }

    #[test]
    fn elements_outside_head_or_in_comments_are_ignored() {
        let doc = format!(
            "<html><head><!-- <script type=\"application/c2pa\">YQ==</script> --></head><body><script type=\"application/c2pa\">{}</script></body></html>",
            base64::encode(b"x")
        );
        assert!(matches!(read_back(doc.as_bytes()), Err(Error::JumbfNotFound)));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let doc = format!(
            "<HTML><HEAD><SCRIPT TYPE='Application/C2PA'>{}</SCRIPT></HEAD></HTML>",
            base64::encode(b"upper")
        );
        assert_eq!(read_back(doc.as_bytes()).unwrap(), b"upper");
    }

    #[test]
    fn remove_restores_the_document() {
        let out = embed(DOC, b"manifest");
        let mut removed = Cursor::new(Vec::new());
        HtmlIO::new("html")
            .remove_c2pa(&mut Cursor::new(out), &mut removed)
            .unwrap();
        assert_eq!(removed.into_inner(), DOC.as_bytes());
    }

    #[test]
    fn patch_replaces_same_size_store() {
        let mut stream = Cursor::new(embed(DOC, b"aaaa"));
        HtmlIO::new("html").patch_c2pa(&mut stream, b"bbbb").unwrap();
        assert_eq!(read_back(&stream.into_inner()).unwrap(), b"bbbb");
    }
}
