// Instead of using random bytes we use random C2PA-box formatted JUMBF bytes. This is for compatibility with
// the JEPG codec, since it assumes the input is already JUMBF formatted (JUMBF is native to JPEG).
pub const RANDOM_JUMBF_BYTES1: &[u8] = &[
    // SuperBox
    0x00, 0x00, 0x00, 0x35, // LBox (total size 53 bytes)
    0x6a, 0x75, 0x6d, 0x62, // TBox ("jumb")
    // DescriptionBox
    0x00, 0x00, 0x00, 0x19, // LBox (size 25 bytes)
    0x6a, 0x75, 0x6d, 0x64, // TBox ("jumd")
    0x63, 0x32, 0x70, 0x61, // Type ("c2pa" in ASCII)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding (8 bytes)
    0x00, 0x00, 0x00, 0x11, // Toggles
    0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x63, 0x6f, 0x6e, 0x74, // Label ("number_cont")
    // ContentBox
    0x00, 0x00, 0x00, 0x12, // LBox (size 18 bytes)
    0x6a, 0x73, 0x6f, 0x6e, // TBox ("json")
    0x5b, 0x30, 0x2c, 0x31, 0x2c, 0x32, 0x2c, 0x33, 0x2c, 0x34, // Payload Data [0,1,2,3,4]
    0x2c, 0x35, 0x2c, 0x36, 0x2c, 0x37, 0x2c, 0x38, 0x2c, 0x39, // Payload Data [5,6,7,8,9]
    0x5d, // Closing bracket for JSON array
];
pub const RANDOM_JUMBF_BYTES2: &[u8] = &[
    // SuperBox
    0x00, 0x00, 0x00, 0x35, // LBox (total size 53 bytes)
    0x6a, 0x75, 0x6d, 0x62, // TBox ("jumb")
    // DescriptionBox
    0x00, 0x00, 0x00, 0x19, // LBox (size 25 bytes)
    0x6a, 0x75, 0x6d, 0x64, // TBox ("jumd")
    0x63, 0x32, 0x70, 0x61, // Type ("c2pa" in ASCII)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding (8 bytes)
    0x00, 0x00, 0x00, 0x11, // Toggles
    0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x63, 0x6f, 0x6e, 0x74, // Label ("number_cont")
    // ContentBox
    0x00, 0x00, 0x00, 0x12, // LBox (size 18 bytes)
    0x6a, 0x73, 0x6f, 0x6e, // TBox ("json")
    0x5b, 0x39, 0x2c, 0x38, 0x2c, 0x37, 0x2c, 0x36, 0x2c, 0x35, // Payload Data [9,8,7,6,5]
    0x2c, 0x34, 0x2c, 0x33, 0x2c, 0x32, 0x2c, 0x31, 0x2c, 0x30, // Payload Data [4,3,2,1,0]
    0x5d, // Closing bracket for JSON array
];
pub const RANDOM_JUMBF_BYTES3: &[u8] = &[
    // SuperBox
    0x00, 0x00, 0x00, 0x2d, // LBox (total size 45 bytes)
    0x6a, 0x75, 0x6d, 0x62, // TBox ("jumb")
    // DescriptionBox
    0x00, 0x00, 0x00, 0x19, // LBox (size 25 bytes)
    0x6a, 0x75, 0x6d, 0x64, // TBox ("jumd")
    0x63, 0x32, 0x70, 0x61, // Type ("c2pa" in ASCII)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding (8 bytes)
    0x00, 0x00, 0x00, 0x11, // Toggles
    0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x63, 0x6f, 0x6e, 0x74, // Label ("number_cont")
    // ContentBox
    0x00, 0x00, 0x00, 0x08, // LBox (size 8 bytes)
    0x6a, 0x73, 0x6f, 0x6e, // TBox ("json")
    0x5b, 0x31, 0x2c, 0x32, 0x2c, 0x33, 0x2c, 0x34, // Payload Data [1,2,3,4]
    0x5d, // Closing bracket for JSON array
];

pub const RANDOM_XMP: &str = r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="contentauth">
    <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
        <rdf:Description rdf:about=""
                xmlns:xmp="http://ns.adobe.com/xap/1.0/"
                xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"
                xmlns:dc="http://purl.org/dc/elements/1.1/"
                xmlns:dcterms="http://purl.org/dc/terms/"
            dcterms:provenance="test"
        </rdf:Description>
    </rdf:RDF>
</x:xmpmeta>"#;

pub const ASSETS: &[Asset] = &[
    Asset::new(
        AssetType::Gif,
        include_bytes!("../../../../tests/fixtures/sample1.gif"),
    ),
    Asset::new(
        AssetType::Svg,
        include_bytes!("../../../../tests/fixtures/sample1.svg"),
    ),
    Asset::new(
        AssetType::Jpeg,
        include_bytes!("../../../../tests/fixtures/empty.jpg"),
    ),
];

#[derive(Debug)]
pub enum AssetType {
    Gif,
    Svg,
    Jpeg,
}

#[derive(Debug)]
pub struct Asset {
    pub bytes: &'static [u8],
    pub extension: &'static str,
    pub mime: &'static str,
    pub max_signature_len: usize,
    pub asset_type: AssetType,

    // TODO: Are the fields below ever needed in a non-testing scenario? Typically a user would attempt
    //       an operation and handle the CodecError::Unsupported from there. To avoid the boilerplate of
    //       that for every function in every test, we pre-define them here. Should we add this functionality
    //       directly to the codecs through the Support trait?
    //
    pub supports_write_c2pa: bool,
    pub supports_remove_c2pa: bool,
    pub supports_write_xmp: bool,
    pub supports_write_xmp_provenance: bool,
    pub supports_remove_xmp: bool,
    pub supports_remove_xmp_provenance: bool,

    pub supports_patch_c2pa: bool,
    pub supports_read_c2pa: bool,
    pub supports_read_xmp: bool,
    pub supports_read_xmp_provenance: bool,

    pub supports_embeddable: bool,
    pub supports_embed: bool,

    pub supports_span: bool,
    pub supports_c2pa_span: bool,
    pub supports_box_span: bool,
    pub supports_bmff_span: bool,
    pub supports_collection_span: bool,

    pub supports_supports_stream: bool,
    pub supports_supports_extension: bool,
    pub supports_supports_mime: bool,
}

impl Asset {
    pub const fn new(asset_type: AssetType, bytes: &'static [u8]) -> Self {
        match asset_type {
            AssetType::Gif => Asset {
                bytes,
                extension: "gif",
                mime: "image/gif",
                max_signature_len: 6,
                asset_type,

                supports_write_c2pa: true,
                supports_remove_c2pa: true,
                supports_write_xmp: true,
                supports_write_xmp_provenance: true,
                supports_remove_xmp: true,
                supports_remove_xmp_provenance: true,

                supports_patch_c2pa: true,
                supports_read_c2pa: true,
                supports_read_xmp: true,
                supports_read_xmp_provenance: false,

                supports_embeddable: true,
                supports_embed: true,

                supports_span: true,
                supports_c2pa_span: true,
                supports_box_span: true,
                supports_bmff_span: true,
                supports_collection_span: true,

                supports_supports_stream: true,
                supports_supports_extension: true,
                supports_supports_mime: true,
            },
            AssetType::Svg => Asset {
                bytes,
                extension: "svg",
                mime: "image/svg+xml",
                max_signature_len: 0,
                asset_type,

                supports_write_c2pa: true,
                supports_remove_c2pa: true,
                supports_write_xmp: false,
                supports_write_xmp_provenance: false,
                supports_remove_xmp: false,
                supports_remove_xmp_provenance: false,

                supports_patch_c2pa: true,
                supports_read_c2pa: true,
                supports_read_xmp: false,
                supports_read_xmp_provenance: false,

                supports_embeddable: true,
                supports_embed: true,

                supports_span: true,
                supports_c2pa_span: true,
                supports_box_span: true,
                supports_bmff_span: true,
                supports_collection_span: true,

                supports_supports_stream: true,
                supports_supports_extension: true,
                supports_supports_mime: true,
            },
            AssetType::Jpeg => Asset {
                bytes,
                extension: "jpg",
                mime: "image/jpeg",
                max_signature_len: 3,
                asset_type,

                supports_write_c2pa: true,
                supports_remove_c2pa: true,
                supports_write_xmp: true,
                supports_write_xmp_provenance: true,
                supports_remove_xmp: true,
                supports_remove_xmp_provenance: true,

                supports_patch_c2pa: false,
                supports_read_c2pa: true,
                supports_read_xmp: true,
                supports_read_xmp_provenance: false,

                supports_embeddable: true,
                supports_embed: true,

                supports_span: true,
                supports_c2pa_span: true,
                supports_box_span: true,
                supports_bmff_span: true,
                supports_collection_span: true,

                supports_supports_stream: true,
                supports_supports_extension: true,
                supports_supports_mime: true,
            },
        }
    }
}
