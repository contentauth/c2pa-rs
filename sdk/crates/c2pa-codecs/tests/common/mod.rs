pub const ASSETS: &[Asset] = &[
    Asset {
        bytes: include_bytes!("../../../../tests/fixtures/sample1.gif"),
        extension: "gif",
        mime: "image/gif",
        max_signature_len: 6,
    },
    Asset {
        bytes: include_bytes!("../../../../tests/fixtures/C.jpg"),
        extension: "jpg",
        mime: "image/jpeg",
        max_signature_len: 6,
    },
];

pub struct Asset {
    pub bytes: &'static [u8],
    pub extension: &'static str,
    pub mime: &'static str,
    pub max_signature_len: usize,
}
