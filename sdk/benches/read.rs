use std::io::Cursor;

use c2pa::Reader;
use criterion::{criterion_group, criterion_main, Criterion};

fn read_jpeg(c: &mut Criterion) {
    let data = include_bytes!("fixtures/100kb-signed.jpg");
    let format = "image/jpeg";

    c.bench_function("read 100kb-signed.jpg (with manifest)", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(data);
            Reader::from_stream(format, &mut stream)
        })
    });
}

fn read_png(c: &mut Criterion) {
    let data = include_bytes!("fixtures/100kb-signed.png");
    let format = "image/png";

    c.bench_function("read 100kb-signed.png (with manifest)", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(data);
            Reader::from_stream(format, &mut stream)
        })
    });
}

fn read_gif(c: &mut Criterion) {
    let data = include_bytes!("fixtures/100kb-signed.gif");
    let format = "image/gif";

    c.bench_function("read 100kb-signed.gif (with manifest)", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(data);
            Reader::from_stream(format, &mut stream)
        })
    });
}

fn read_tiff(c: &mut Criterion) {
    let data = include_bytes!("fixtures/100kb-signed.tiff");
    let format = "image/tiff";

    c.bench_function("read 100kb-signed.tiff (with manifest)", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(data);
            Reader::from_stream(format, &mut stream)
        })
    });
}

fn read_svg(c: &mut Criterion) {
    let data = include_bytes!("fixtures/100kb-signed.svg");
    let format = "image/svg+xml";

    c.bench_function("read 100kb-signed.svg (with manifest)", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(data);
            Reader::from_stream(format, &mut stream)
        })
    });
}

// TODO: Add back when we support pdf signing.
// https://github.com/contentauth/c2pa-rs/issues/527
// fn read_pdf(c: &mut Criterion) {
//     let data = include_bytes!("fixtures/100kb-signed.pdf");
//     let format = "application/pdf";

//     c.bench_function("read 100kb-signed.pdf (with manifest)", |b| {
//         b.iter(|| {
//             let mut stream = Cursor::new(data);
//             Reader::from_stream(format, &mut stream)
//         })
//     });
// }

fn read_mp3(c: &mut Criterion) {
    let data = include_bytes!("fixtures/100kb-signed.mp3");
    let format = "audio/mpeg";

    c.bench_function("read 100kb-signed.mp3 (with manifest)", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(data);
            Reader::from_stream(format, &mut stream)
        })
    });
}

fn read_mp4(c: &mut Criterion) {
    let data = include_bytes!("fixtures/100kb-signed.mp4");
    let format = "video/mp4";

    c.bench_function("read 100kb-signed.mp4 (with manifest)", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(data);
            Reader::from_stream(format, &mut stream)
        })
    });
}

fn read_wav(c: &mut Criterion) {
    let data = include_bytes!("fixtures/100kb-signed.wav");
    let format = "audio/wav";

    c.bench_function("read 100kb-signed.wav (with manifest)", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(data);
            Reader::from_stream(format, &mut stream)
        })
    });
}

criterion_group!(
    benches, read_jpeg, read_png, read_gif, read_tiff, read_svg, read_pdf, read_mp3, read_mp4,
    read_wav
);
criterion_main!(benches);
