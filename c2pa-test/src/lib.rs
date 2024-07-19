/// Convenience structs to reference test assets, including manifests, certs, images, videos, zips, etc.
///
/// Provides numerous methods to
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use c2pa::{format_from_path, Result};

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
        let path = PathBuf::from(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), sub_path));
        Self {
            stream: Cursor::new(ASSETS.get(sub_path).unwrap()),
            format: format_from_path(&path).unwrap(),
            path,
        }
    }

    #[cfg(not(feature = "include_bytes"))]
    pub fn new(path: &str) -> Self {
        // TODO: add prefix to path
        Ok(Self {
            format: format_from_path(&path).unwrap(),
            stream: std::fs::File::open(&path).expect("TODO"),
            path,
        })
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

// TODO: these will all be removed in favor of the macros
impl Asset {
    pub fn arbitrary() -> Result<Asset> {
        todo!()
    }

    pub fn exactly(kind: &str) -> Result<Asset> {
        todo!()
    }

    pub fn any(kind: &str) -> Result<Asset> {
        todo!()
    }

    pub fn every(kind: &str) -> Result<Vec<Asset>> {
        todo!()
    }

    pub fn all(kinds: &[&str]) -> Result<Vec<Asset>> {
        todo!()
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

#[macro_export]
macro_rules! arbitrary {
    () => {
        Asset::new("jpg/C.jpg")
    };
}

#[macro_export]
macro_rules! exactly {
    ($kind:expr) => {{
        Asset::new($kind)
    }};
}

#[macro_export]
macro_rules! any {
    ($kind:expr) => {
        for path in c2pa_test::ASSETS.keys() {
            // TODO: same here
            if path.starts_with($kind) {
                return Asset::new(path);
            }
        }

        unreachable!()
    };
}

#[macro_export]
macro_rules! every {
    ($kind:expr) => {{
        let mut assets = Vec::new();
        for path in c2pa_test::ASSETS.keys() {
            // TODO: we can precompute lists of them in build.rs
            if path.starts_with($kind) {
                assets.push(Asset::new(path));
            }
        }
        assets
    }};
}

#[macro_export]
macro_rules! all {
    ($kinds:expr) => {{
        let mut assets = Vec::new();
        for kind in $kinds {
            for path in c2pa_test::ASSETS.keys() {
                // TODO: same here
                if path.starts_with(kind) {
                    assets.push(Asset::new(path))
                }
            }
        }
        assets
    }};
}
