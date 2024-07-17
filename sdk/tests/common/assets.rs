use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use c2pa::{format_from_path, Result};

const ASSETS_PATH: &str = "tests/fixtures/assets";

#[derive(Debug)]
pub struct Asset {
    stream: File,
    // We store the path to make it easier to debug.
    path: PathBuf,
    format: String,
}

impl Asset {
    pub fn new(stream: File, path: PathBuf) -> Self {
        Self {
            format: format_from_path(&path).unwrap(),
            stream,
            path,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    // We clone for convenience w/ Reader.
    pub fn format(&self) -> String {
        self.format.clone()
    }

    pub fn to_bytes(&mut self) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.stream.read_to_end(&mut buffer)?;
        Ok(buffer)
    }
}

impl Read for Asset {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Seek for Asset {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.stream.seek(pos)
    }
}

pub fn test_asset(kind: &str) -> Result<Asset> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(ASSETS_PATH)
        .join(kind);

    Ok(Asset::new(File::open(&path)?, path))
}

pub fn test_asset_kind(kind: &str) -> Result<Vec<Asset>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(ASSETS_PATH)
        .join(kind);

    let mut assets = Vec::new();
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        assets.push(Asset::new(File::open(&path)?, path));
    }

    Ok(assets)
}

pub fn test_asset_kinds(kinds: &[&str]) -> Result<Vec<Asset>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(ASSETS_PATH);

    let mut assets = Vec::new();
    for kind in kinds {
        for entry in fs::read_dir(root.join(kind))? {
            let path = entry?.path();
            assets.push(Asset::new(File::open(&path)?, path));
        }
    }

    Ok(assets)
}
