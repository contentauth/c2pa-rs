use std::{
    fs::File,
    io::{Read, Seek},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    assertions::AssetType, asset_handlers::zip_io, hash_stream_by_alg,
    hash_utils::verify_stream_by_alg, Error, HashRange, Result,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Default)]
pub struct CollectionHash {
    pub uris: Vec<UriHashedDataMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub zip_central_directory_hash: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UriHashedDataMap {
    pub uri: PathBuf,

    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    #[serde(rename = "dc:format", skip_serializing_if = "Option::is_none")]
    pub dc_format: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_types: Option<Vec<AssetType>>,
}

impl CollectionHash {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_uri_map(&mut self, uri_map: UriHashedDataMap) {
        self.uris.push(uri_map);
    }

    // The base path MUST be the folder of the manifest. A URI MUST NOT reference a path outside of that folder.
    pub fn gen_hash<R>(&mut self, base_path: &Path) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        self.validate_paths()?;

        let alg = self.alg().to_owned();
        for uri_map in &mut self.uris {
            let path = base_path.join(&uri_map.uri);
            let mut file = File::open(path)?;
            let file_len = file.metadata()?.len();

            uri_map.hash = hash_stream_by_alg(
                &alg,
                &mut file,
                // TODO: temp unwrap
                #[allow(clippy::unwrap_used)]
                Some(vec![HashRange::new(0, usize::try_from(file_len).unwrap())]),
                false,
            )?;
        }

        Ok(())
    }

    pub fn verify_hash<R>(&self, alg: Option<&str>, base_path: &Path) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        self.validate_paths()?;

        let alg = alg.unwrap_or_else(|| self.alg());
        for uri_map in &self.uris {
            let path = base_path.join(&uri_map.uri);
            let mut file = File::open(&path)?;
            let file_len = file.metadata()?.len();

            if !verify_stream_by_alg(
                alg,
                &uri_map.hash,
                &mut file,
                // TODO: temp unwrap
                #[allow(clippy::unwrap_used)]
                Some(vec![HashRange::new(0, usize::try_from(file_len).unwrap())]),
                false,
            ) {
                return Err(Error::HashMismatch(format!(
                    "hash for {} does not match",
                    path.display()
                )));
            }
        }

        Ok(())
    }

    // We overwrite all URIs with all existing URIs in the ZIP because all URIs in the ZIP represent all
    // possible valid URIs — we don't want duplicates!
    pub fn gen_uris_from_zip_stream<R>(&mut self, stream: &mut R) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        self.uris = zip_io::uri_maps(stream)?;
        Ok(())
    }

    pub fn gen_hash_from_zip_stream<R>(&mut self, stream: &mut R) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        let alg = self.alg().to_owned();

        let zip_central_directory_inclusions = zip_io::central_directory_inclusions(stream)?;
        let zip_central_directory_hash =
            hash_stream_by_alg(&alg, stream, Some(zip_central_directory_inclusions), false)?;
        if zip_central_directory_hash.is_empty() {
            return Err(Error::BadParam("could not generate data hash".to_string()));
        }
        self.zip_central_directory_hash = Some(zip_central_directory_hash);

        let hash_ranges = zip_io::uri_inclusions(stream, &self.uris)?;
        for (uri_map, hash_range) in self.uris.iter_mut().zip(hash_ranges) {
            let hash = hash_stream_by_alg(&alg, stream, Some(vec![hash_range]), false)?;
            if hash.is_empty() {
                return Err(Error::BadParam("could not generate data hash".to_string()));
            }

            uri_map.hash = hash;
        }

        Ok(())
    }

    pub fn verify_zip_stream_hash<R>(&self, stream: &mut R, alg: Option<&str>) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        let alg = alg.unwrap_or_else(|| self.alg());
        let central_directory_hash = match &self.zip_central_directory_hash {
            Some(hash) => Ok(hash),
            None => Err(Error::BadParam(
                "Missing zip central directory hash".to_owned(),
            )),
        }?;
        let zip_central_directory_inclusions = zip_io::central_directory_inclusions(stream)?;
        if !verify_stream_by_alg(
            alg,
            central_directory_hash,
            stream,
            Some(zip_central_directory_inclusions),
            false,
        ) {
            return Err(Error::HashMismatch(
                "Hashes do not match for zip central directory".to_owned(),
            ));
        }

        let hash_ranges = zip_io::uri_inclusions(stream, &self.uris)?;
        for (uri_map, hash_range) in self.uris.iter().zip(hash_ranges) {
            if !verify_stream_by_alg(alg, &uri_map.hash, stream, Some(vec![hash_range]), false) {
                return Err(Error::HashMismatch(format!(
                    "hash for {} does not match",
                    uri_map.uri.display()
                )));
            }
        }

        Ok(())
    }

    fn alg(&self) -> &str {
        self.alg.as_deref().unwrap_or("sha256")
    }

    fn validate_paths(&self) -> Result<()> {
        for uri_map in &self.uris {
            for component in uri_map.uri.components() {
                match component {
                    Component::CurDir | Component::ParentDir => {
                        return Err(Error::BadParam(format!(
                            "URI `{}` must not contain relative components: `.` nor `..`",
                            uri_map.uri.display()
                        )));
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const ZIP_SAMPLE1: &[u8] = include_bytes!("../../tests/fixtures/sample1.zip");

    #[test]
    fn test_zip_uri_gen() -> Result<()> {
        let mut stream = Cursor::new(ZIP_SAMPLE1);

        let mut collection = CollectionHash::new();
        collection.gen_uris_from_zip_stream(&mut stream)?;

        assert_eq!(
            collection.uris.first(),
            Some(&UriHashedDataMap {
                uri: PathBuf::from("sample1/test1.txt"),
                hash: Vec::new(),
                size: Some(44),
                dc_format: None,
                data_types: None
            })
        );
        assert_eq!(
            collection.uris.get(1),
            Some(&UriHashedDataMap {
                uri: PathBuf::from("sample1/test1/test1.txt"),
                hash: Vec::new(),
                size: Some(87),
                dc_format: None,
                data_types: None
            })
        );
        assert_eq!(
            collection.uris.get(2),
            Some(&UriHashedDataMap {
                uri: PathBuf::from("sample1/test1/test2.txt"),
                hash: Vec::new(),
                size: Some(148),
                dc_format: None,
                data_types: None
            })
        );
        assert_eq!(
            collection.uris.get(3),
            Some(&UriHashedDataMap {
                uri: PathBuf::from("sample1/test1/test3.txt"),
                hash: Vec::new(),
                size: Some(186),
                dc_format: None,
                data_types: None
            })
        );
        assert_eq!(
            collection.uris.get(4),
            Some(&UriHashedDataMap {
                uri: PathBuf::from("sample1/test2.txt"),
                hash: Vec::new(),
                size: Some(304),
                dc_format: None,
                data_types: None
            })
        );
        assert_eq!(collection.uris.len(), 5);

        Ok(())
    }

    #[test]
    fn test_zip_hash_gen() -> Result<()> {
        let mut stream = Cursor::new(ZIP_SAMPLE1);

        // TODO: blocked by zip_io::central_directory_inclusions
        // let mut collection = CollectionHash::new();
        // collection.gen_uris_from_zip_stream(&mut stream)?;
        // collection.gen_hash_from_zip_stream(&mut stream)?;

        // TODO: assert central dir hash + uri map hashes

        Ok(())
    }
}
