pub const JPEGS: &[&[u8]] = &[
    include_bytes!("../fixtures/boxhash.jpg"),
    include_bytes!("../fixtures/C.jpg"),
    include_bytes!("../fixtures/CA.jpg"),
    include_bytes!("../fixtures/CIE-sig-CA.jpg"),
    include_bytes!("../fixtures/cloud.jpg"),
    include_bytes!("../fixtures/cloudx.jpg"),
    include_bytes!("../fixtures/E-sig-CA.jpg"),
    include_bytes!("../fixtures/earth_apollo17.jpg"),
    include_bytes!("../fixtures/IMG_0003.jpg"),
    include_bytes!("../fixtures/legacy_ingredient_hash.jpg"),
    include_bytes!("../fixtures/no_manifest.jpg"),
    include_bytes!("../fixtures/P1000827.jpg"),
    include_bytes!("../fixtures/prerelease.jpg"),
    include_bytes!("../fixtures/XCA.jpg"),
];

pub const PNGS: &[&[u8]] = &[
    include_bytes!("../fixtures/exp-test1.png"),
    include_bytes!("../fixtures/libpng-test_with_url.png"),
    include_bytes!("../fixtures/libpng-test.png"),
    include_bytes!("../fixtures/sample1.png"),
];

pub const PDFS: &[&[u8]] = &[
    include_bytes!("../fixtures/basic-annotation.pdf"),
    include_bytes!("../fixtures/basic-attachments.pdf"),
    include_bytes!("../fixtures/basic-no-xmp.pdf"),
    include_bytes!("../fixtures/basic-password.pdf"),
    include_bytes!("../fixtures/basic-retest.pdf"),
    include_bytes!("../fixtures/basic-signed.pdf"),
    include_bytes!("../fixtures/basic.pdf"),
    include_bytes!("../fixtures/express-signed.pdf"),
    include_bytes!("../fixtures/express.pdf"),
];

pub const BMFFS: &[&[u8]] = &[
    include_bytes!("../fixtures/legacy.mp4"),
    include_bytes!("../fixtures/video1.mp4"),
    include_bytes!("../fixtures/sample1.avif"),
    include_bytes!("../fixtures/sample1.heic"),
    include_bytes!("../fixtures/sample1.heif"),
];

pub const RIFFS: &[&[u8]] = &[
    include_bytes!("../fixtures/mars.webp"),
    include_bytes!("../fixtures/sample1.webp"),
    include_bytes!("../fixtures/test_lossless.webp"),
    include_bytes!("../fixtures/test_xmp.webp"),
    include_bytes!("../fixtures/test.webp"),
    include_bytes!("../fixtures/test.avi"),
    include_bytes!("../fixtures/sample1.wav"),
];

pub const SVGS: &[&[u8]] = &[
    include_bytes!("../fixtures/sample1.svg"),
    include_bytes!("../fixtures/sample2.svg"),
    include_bytes!("../fixtures/sample3.svg"),
    include_bytes!("../fixtures/sample4.svg"),
];

pub const MP3S: &[&[u8]] = &[include_bytes!("../fixtures/sample1.mp3")];

pub const TIFFS: &[&[u8]] = &[include_bytes!("../fixtures/TUSCANY.TIF")];

pub const ASSETS: &[&[&[u8]]] = &[JPEGS, PNGS, PDFS, BMFFS, RIFFS, SVGS, MP3S, TIFFS];

pub fn iter_assets() -> impl Iterator<Item = &'static [u8]> {
    ASSETS.iter().flat_map(|&asset| asset.iter()).copied()
}

pub fn iter_num_assets(num: usize) -> impl Iterator<Item = &'static [u8]> {
    ASSETS
        .iter()
        .flat_map(move |&asset| asset.iter().take(num))
        .copied()
}
