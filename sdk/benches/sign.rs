use std::io::Cursor;

use c2pa::{Builder, CallbackSigner, SigningAlg};
use criterion::{criterion_group, criterion_main, Criterion};

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");
const MANIFEST_JSON: &str = include_str!("../tests/fixtures/simple_manifest.json");

fn create_signer() -> CallbackSigner {
    let ed_signer =
        |_context: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS)
}

fn create_builder() -> Builder {
    Builder::from_json(MANIFEST_JSON).expect("failed to create builder from manifest JSON")
}

fn sign_jpeg(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let mut source = Cursor::new(include_bytes!("fixtures/100kb.jpg"));
    let mut dest = Cursor::new(Vec::new());
    let format = "image/jpeg";

    c.bench_function("sign 100kb jpeg", |b| {
        b.iter(|| {
            source.set_position(0);
            dest.set_position(0);
            dest.get_mut().clear();
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn sign_png(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let mut source = Cursor::new(include_bytes!("fixtures/100kb.png"));
    let mut dest = Cursor::new(Vec::new());
    let format = "image/png";

    c.bench_function("sign 100kb png", |b| {
        b.iter(|| {
            source.set_position(0);
            dest.set_position(0);
            dest.get_mut().clear();
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn sign_gif(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let mut source = Cursor::new(include_bytes!("fixtures/100kb.gif"));
    let mut dest = Cursor::new(Vec::new());
    let format = "image/gif";

    c.bench_function("sign 100kb gif", |b| {
        b.iter(|| {
            source.set_position(0);
            dest.set_position(0);
            dest.get_mut().clear();
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn sign_tiff(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let mut source = Cursor::new(include_bytes!("fixtures/100kb.tiff"));
    let mut dest = Cursor::new(Vec::new());
    let format = "image/tiff";

    c.bench_function("sign 100kb tiff", |b| {
        b.iter(|| {
            source.set_position(0);
            dest.set_position(0);
            dest.get_mut().clear();
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn sign_svg(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let mut source = Cursor::new(include_bytes!("fixtures/100kb.svg"));
    let mut dest = Cursor::new(Vec::new());
    let format = "image/svg+xml";

    c.bench_function("sign 100kb svg", |b| {
        b.iter(|| {
            source.set_position(0);
            dest.set_position(0);
            dest.get_mut().clear();
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

// TODO: Add back when we support pdf signing.
// https://github.com/contentauth/c2pa-rs/issues/527
// fn sign_pdf(c: &mut Criterion) {
//     let mut builder = create_builder();
//     let signer = create_signer();
//     let mut source = Cursor::new(include_bytes!("fixtures/100kb.pdf"));
//     let mut dest = Cursor::new(Vec::new());
//     let format = "application/pdf";

//     c.bench_function("sign 100kb pdf", |b| {
//         b.iter(|| {
//             source.set_position(0);
//             dest.set_position(0);
//             dest.get_mut().clear();
//             builder.sign(&signer, format, &mut source, &mut dest)
//         })
//     });
// }

fn sign_mp3(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let mut source = Cursor::new(include_bytes!("fixtures/100kb.mp3"));
    let mut dest = Cursor::new(Vec::new());
    let format = "audio/mpeg";

    c.bench_function("sign 100kb mp3", |b| {
        b.iter(|| {
            source.set_position(0);
            dest.set_position(0);
            dest.get_mut().clear();
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn sign_mp4(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let mut source = Cursor::new(include_bytes!("fixtures/100kb.mp4"));
    let mut dest = Cursor::new(Vec::new());
    let format = "video/mp4";

    c.bench_function("sign 100kb mp4", |b| {
        b.iter(|| {
            source.set_position(0);
            dest.set_position(0);
            dest.get_mut().clear();
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn sign_wav(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let mut source = Cursor::new(include_bytes!("fixtures/100kb.wav"));
    let mut dest = Cursor::new(Vec::new());
    let format = "audio/wav";

    c.bench_function("sign 100kb wav", |b| {
        b.iter(|| {
            source.set_position(0);
            dest.set_position(0);
            dest.get_mut().clear();
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

criterion_group!(
    benches, sign_jpeg, sign_png, sign_gif, sign_tiff, sign_svg, sign_mp3, sign_mp4, sign_wav
);
criterion_main!(benches);
