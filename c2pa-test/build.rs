use std::{
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
};

// TODO; cleanup fixtures folder more and we don't need this
const ASSET_TYPES: &[&str] = &[
    "cert", "manifest", "jpeg", "bmff", "gif", "mp3", "pdf", "png", "riff", "svg", "tiff",
];

// TODO: only run if include_bytes is enabled
fn main() {
    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("assets.rs");
    let mut file = BufWriter::new(File::create(&path).unwrap());

    let mut map = phf_codegen::Map::new();
    for asset_type in ASSET_TYPES {
        // TODO: CARGO_MANIFEST_DIR
        for asset in fs::read_dir(format!("../sdk/tests/fixtures/{asset_type}")).unwrap() {
            let asset = asset.unwrap();
            let path = asset.path();

            // TODO: temp
            if path.is_dir() {
                continue;
            }

            let file_name = path.file_name().unwrap().to_str().unwrap();
            let sub_path = format!("{asset_type}/{file_name}");

            let bytes = format!(
                r#"include_bytes!("{}/../sdk/tests/fixtures/{}")"#,
                env!("CARGO_MANIFEST_DIR"),
                sub_path
            );

            map.entry(sub_path, &bytes);
        }
    }

    write!(
        &mut file,
        "pub static ASSETS: phf::Map<&'static str, &[u8]> = {}",
        map.build()
    )
    .unwrap();
    writeln!(&mut file, ";").unwrap();
}
