use std::io::Cursor;

use c2pa_codecs::{
    codecs::{gif::GifCodec, svg::SvgCodec},
    Decode,
};

// TODO: add all codecs and add way to choose what to fuzz, reading/writing/c2pa/xmp/etc.
fn main() {
    afl::fuzz!(|data: &[u8]| {
        let src = Cursor::new(data);

        // let mut c = GifCodec::new(src);
        // let _ = c.read_c2pa();
        // let _ = c.read_xmp();

        let mut c = SvgCodec::new(src);
        let _ = c.read_c2pa();
        let _ = c.read_xmp();

        // let mut c = C2paCodec::new(src);
        // let _ = c.read_c2pa();
        // let _ = c.read_xmp();
    });
}
