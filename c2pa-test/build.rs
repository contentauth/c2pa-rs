use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

use phf_codegen::Map;
use walkdir::WalkDir;

const TESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../sdk/tests");

const DIRS: &[&str] = &["fixtures", "assets"];

// TODO: we can get away without using this for non include_bytes
pub fn main() {
    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("assets.rs");
    let mut file = BufWriter::new(File::create(&path).unwrap());

    let mut map = Map::new();
    for dir in DIRS {
        let dir = format!("{TESTS}/{dir}");
        for f in WalkDir::new(&dir) {
            let f = f.unwrap();
            let path = f.path();
            if !path.is_dir() {
                println!("cargo::rerun-if-changed={}", path.display());

                let sub_path = path
                    .strip_prefix(&dir)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();

                // TODO: in not(include_bytes) we don't need to do this, can we store a stream or maybe just use a set instead?
                let bytes = format!(r#"include_bytes!("{}")"#, path.display());

                map.entry(sub_path, &bytes);
            }
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
