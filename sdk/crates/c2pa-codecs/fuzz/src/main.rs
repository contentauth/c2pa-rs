use std::io::Cursor;

use c2pa_codecs::{codecs::gif::GifCodec, Decode};

// TODO: add all codecs and add way to choose what to fuzz, reading/writing/c2pa/xmp/etc.
fn main() {
    afl::fuzz!(|data: &[u8]| {
        let src = Cursor::new(data);

        let mut gif = GifCodec::new(src);
        let _ = gif.read_c2pa();
        let _ = gif.read_xmp();
    });
}
