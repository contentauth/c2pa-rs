/// Convenience structs to reference test assets, including manifests, certs, images, videos, zips, etc.
///
/// Provides numerous methods to
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use c2pa::{format_from_path, Result};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../sdk/tests/fixtures");

#[cfg(feature = "include_bytes")]
include!(concat!(env!("OUT_DIR"), "/assets.rs"));

#[cfg(feature = "include_bytes")]
#[derive(Debug)]
pub struct Asset {
    stream: Cursor<&'static [u8]>,
    path: PathBuf,
    format: String,
}

#[cfg(not(feature = "include_bytes"))]
#[derive(Debug)]
pub struct Asset {
    stream: std::fs::File,
    path: PathBuf,
    format: String,
}

impl Asset {
    #[cfg(feature = "include_bytes")]
    pub fn new(sub_path: &str) -> Self {
        let path = PathBuf::from(format!("{FIXTURES}/{}", sub_path));
        Self {
            stream: Cursor::new(ASSETS.get(sub_path).unwrap()),
            format: format_from_path(&path).unwrap(),
            path,
        }
    }

    #[cfg(not(feature = "include_bytes"))]
    pub fn new(sub_path: &str) -> Self {
        let path = PathBuf::from(format!("{FIXTURES}/{}", sub_path));
        Self {
            stream: std::fs::File::open(&path).expect("TODO"),
            format: format_from_path(&path).unwrap(),
            path,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn format(&self) -> String {
        self.format.clone()
    }

    #[cfg(feature = "include_bytes")]
    pub fn to_bytes(&mut self) -> Result<Vec<u8>> {
        Ok((*self.stream.get_ref()).to_owned())
    }

    #[cfg(not(feature = "include_bytes"))]
    pub fn to_bytes(&mut self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.stream.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    #[cfg(feature = "include_bytes")]
    pub fn to_string(&mut self) -> Result<String> {
        // TODO: temp unwrap
        Ok(String::from_utf8(self.to_bytes()?).unwrap())
    }

    #[cfg(not(feature = "include_bytes"))]
    pub fn to_string(&mut self) -> Result<String> {
        let mut string = String::new();
        self.stream.read_to_string(&mut string)?;
        Ok(string)
    }
}

impl Asset {
    pub fn arbitrary() -> Asset {
        Asset::new("jpg/C.jpg")
    }

    pub fn exactly(kind: &str) -> Asset {
        Asset::new(kind)
    }

    pub fn any(kind: &str) -> Asset {
        for path in ASSETS.keys() {
            // TODO: we can precompute lists of them in build.rs
            if path.starts_with(kind) {
                return Asset::new(path);
            }
        }

        todo!()
    }

    pub fn every(kind: &str) -> Vec<Asset> {
        let mut assets = Vec::new();
        for path in ASSETS.keys() {
            // TODO: same here
            if path.starts_with(kind) {
                assets.push(Asset::new(path));
            }
        }
        assets
    }

    pub fn all(kinds: &[&str]) -> Vec<Asset> {
        let mut assets = Vec::new();
        for kind in kinds {
            for path in ASSETS.keys() {
                // TODO: same here
                if path.starts_with(kind) {
                    assets.push(Asset::new(path))
                }
            }
        }
        assets
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
