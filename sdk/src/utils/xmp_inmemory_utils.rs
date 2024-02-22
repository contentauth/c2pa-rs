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

use std::io::Cursor;

use fast_xml::{
    events::{BytesEnd, BytesStart, Event},
    Reader, Writer,
};
use log::error;

use crate::{
    asset_io::CAIRead, jumbf_io::get_cailoader_handler, utils::hash_utils::vec_compare, Error,
    Result,
};

const RDF_DESCRIPTION: &[u8] = b"rdf:Description";

pub const MIN_XMP: &str = r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="XMP Core 6.0.0"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" > </rdf:Description></rdf:RDF> </x:xmpmeta> "#;

#[derive(Default)]
pub struct XmpInfo {
    pub document_id: Option<String>,
    pub instance_id: Option<String>,
    pub provenance: Option<String>,
}

impl XmpInfo {
    /// search xmp data for provenance, documentID and instanceID
    pub fn from_source(source: &mut dyn CAIRead, format: &str) -> Self {
        let xmp = get_cailoader_handler(format).and_then(|cai_loader| {
            // read xmp if available
            cai_loader.read_xmp(source)
        });

        // todo: do this in one pass through XMP
        let provenance = xmp.as_deref().and_then(extract_provenance);
        let document_id = xmp.as_deref().and_then(extract_document_id);
        let instance_id = xmp.as_deref().and_then(extract_instance_id);
        Self {
            document_id,
            instance_id,
            provenance,
        }
    }
}

/// Extract an a value from XMP using a key
fn extract_xmp_key(xmp: &str, key: &str) -> Option<String> {
    let mut reader = Reader::from_str(xmp);
    reader.trim_text(true);
    let mut buf = Vec::new();

    loop {
        match reader.read_event(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                if e.name() == RDF_DESCRIPTION {
                    // attribute case
                    let value = e.attributes().find(|a| {
                        if let Ok(attribute) = a {
                            vec_compare(attribute.key, key.as_bytes())
                        } else {
                            false
                        }
                    });
                    if let Some(Ok(attribute)) = value {
                        if let Ok(s) = String::from_utf8(attribute.value.to_vec()) {
                            return Some(s);
                        }
                    }
                } else if e.name() == key.as_bytes() {
                    // tag case
                    let mut buf: Vec<u8> = Vec::new();
                    if let Ok(s) = reader.read_text(e.name(), &mut buf) {
                        return Some(s);
                    }
                }
            }
            Ok(Event::Eof) => break,
            _ => {}
        }
        buf.clear();
    }
    None
}

/// Add a value to XMP using a key, replaces the value if the key exists
fn add_xmp_key(xmp: &str, key: &str, value: &str) -> Result<String> {
    let mut reader = Reader::from_str(xmp);
    reader.trim_text(true);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();
    let mut added = false;
    loop {
        match reader.read_event(&mut buf) {
            Ok(Event::Start(ref e)) if e.name() == RDF_DESCRIPTION => {
                // creates a new element
                let mut elem = BytesStart::owned(RDF_DESCRIPTION.to_vec(), RDF_DESCRIPTION.len());
                for attr in e.attributes() {
                    if let Ok(attr) = attr {
                        if attr.key == key.as_bytes() {
                            // replace the key/value if it exists
                            elem.push_attribute((key, value));
                            added = true;
                        } else {
                            // add all other existing elements
                            elem.extend_attributes([attr]);
                        }
                    } else {
                        error!("Error at position {}", reader.buffer_position());
                        return Err(Error::XmpReadError);
                    }
                }
                if !added {
                    // didn't exist, so add it
                    elem.push_attribute((key, value));
                }
                // writes the event to the writer
                assert!(writer.write_event(Event::Start(elem)).is_ok());
            }
            Ok(Event::End(ref e)) if e.name() == b"this_tag" => {
                assert!(writer
                    .write_event(Event::End(BytesEnd::borrowed(b"my_elem")))
                    .is_ok());
            }
            Ok(Event::Eof) => break,
            Ok(e) => assert!(writer.write_event(e).is_ok()),
            Err(e) => {
                error!("Error at position {}: {:?}", reader.buffer_position(), e);
                return Err(Error::XmpWriteError);
            }
        }
    }
    buf.clear();
    let result = writer.into_inner().into_inner();
    String::from_utf8(result).map_err(|_e| Error::XmpWriteError)
}

/// extract the dc:provenance value from xmp
pub fn extract_provenance(xmp: &str) -> Option<String> {
    extract_xmp_key(xmp, "dcterms:provenance")
}

/// extract the xmpMM:InstanceID value from xmp
fn extract_instance_id(xmp: &str) -> Option<String> {
    extract_xmp_key(xmp, "xmpMM:InstanceID")
}

/// extract the "xmpMM:DocumentID" value from xmp
fn extract_document_id(xmp: &str) -> Option<String> {
    extract_xmp_key(xmp, "xmpMM:DocumentID")
}

/// add or replace a dc:provenance value to xmp, including dc:terms if needed
pub fn add_provenance(xmp: &str, provenance: &str) -> Result<String> {
    let xmp = add_xmp_key(xmp, "xmlns:dcterms", "http://purl.org/dc/terms/")?;
    add_xmp_key(&xmp, "dcterms:provenance", provenance)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    //use env_logger;
    use super::*;

    const XMP_DATA: &str = r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
    <x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="contentauth">
        <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
            <rdf:Description rdf:about=""
                    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
                    xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"
                    xmlns:dc="http://purl.org/dc/elements/1.1/"
                    xmlns:dcterms="http://purl.org/dc/terms/"
                xmpMM:DocumentID="xmp.did:cb9f5498-bb58-4572-8043-8c369e6bfb9b"
                xmpMM:InstanceID="xmp.iid:cb9f5498-bb58-4572-8043-8c369e6bfb9b"
                dcterms:provenance="self#jumbf=c2pa/contentauth:urn:uuid:a58065fb-79ae-4eb3-87b9-a19830860059/c2pa.claim"
                dc:format="image/jpeg">
            </rdf:Description>
        </rdf:RDF>
    </x:xmpmeta>"#;

    const PROVENANCE: &str =
        "self#jumbf=c2pa/contentauth:urn:uuid:a58065fb-79ae-4eb3-87b9-a19830860059/c2pa.claim";

    #[test]
    fn read_xmp() {
        let provenance = extract_provenance(XMP_DATA);
        assert_eq!(provenance, Some("self#jumbf=c2pa/contentauth:urn:uuid:a58065fb-79ae-4eb3-87b9-a19830860059/c2pa.claim".to_owned()));
        let document_id = extract_document_id(XMP_DATA);
        assert_eq!(
            document_id,
            Some("xmp.did:cb9f5498-bb58-4572-8043-8c369e6bfb9b".to_owned())
        );
        let instance_id = extract_instance_id(XMP_DATA);
        assert_eq!(
            instance_id,
            Some("xmp.iid:cb9f5498-bb58-4572-8043-8c369e6bfb9b".to_owned())
        );
        let unicorn = extract_xmp_key(XMP_DATA, "unicorn");
        assert_eq!(unicorn, None);
        let bad_xmp = extract_xmp_key("bad xmp", "unicorn");
        assert_eq!(bad_xmp, None);
    }

    #[test]
    fn add_xmp() {
        let xmp = add_provenance(XMP_DATA, PROVENANCE).expect("adding provenance");
        let unicorn = extract_provenance(&xmp);
        println!("{xmp}");
        assert_eq!(unicorn, Some(PROVENANCE.to_string()));

        let xmp = add_provenance(MIN_XMP, PROVENANCE).expect("adding provenance");
        let unicorn = extract_provenance(&xmp);
        println!("{xmp}");
        assert_eq!(unicorn, Some(PROVENANCE.to_string()));
    }
}
