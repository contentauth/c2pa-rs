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
    pub fn new(path: PathBuf) -> Result<Self> {
        Ok(Self {
            format: format_from_path(&path).unwrap(),
            stream: File::open(&path)?,
            path,
        })
    }

    pub fn exactly(kind: &str) -> Result<Self> {
        let path = fixtures().join(kind);
        Asset::new(path)
    }

    pub fn any(kind: &str) -> Result<Self> {
        let path = fixtures().join(kind);
        let path = fs::read_dir(&path)?.next().unwrap()?.path();
        Asset::new(path)
    }

    pub fn every(kind: &str) -> Result<Vec<Self>> {
        let path = fixtures().join(kind);

        let mut assets = Vec::new();
        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            assets.push(Asset::new(path)?);
        }

        Ok(assets)
    }

    pub fn all(kinds: &[&str]) -> Result<Vec<Self>> {
        let fixtures = fixtures();

        let mut assets = Vec::new();
        for kind in kinds {
            for entry in fs::read_dir(fixtures.join(kind))? {
                let path = entry?.path();
                assets.push(Asset::new(path)?);
            }
        }

        Ok(assets)
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

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(ASSETS_PATH)
}
