use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Seek},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::{labels::COLLECTION_HASH, AssetType},
    asset_handlers::zip_io::{zip_central_directory_range, zip_uri_ranges},
    hash_stream_by_alg,
    hash_utils::verify_stream_by_alg,
    utils::mime,
    validation_status::{
        ASSERTION_COLLECTIONHASH_INCORRECT_FILE_COUNT, ASSERTION_COLLECTIONHASH_INVALID_URI,
        ASSERTION_COLLECTIONHASH_MALFORMED,
    },
    Error, HashRange, Result,
};

const ASSERTION_CREATION_VERSION: usize = 1;

/// A collection hash is used to hash multiple files within a collection (e.g. a folder or a zip file).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CollectionHash {
    // We use a hash map to avoid potential duplicates.
    //
    /// Map of file path to their metadata for the collection.
    pub uris: HashMap<PathBuf, UriHashedDataMap>,

    /// Algorithm used to hash the files.
    pub alg: String,

    /// Hash of the ZIP central directory.
    ///
    /// This field only needs to be specified if the collection hash is for a ZIP file.
    #[serde(with = "serde_bytes", default, skip_serializing_if = "Option::is_none")]
    pub zip_central_directory_hash: Option<Vec<u8>>,
}

/// Information about a file in a [`CollectionHash`][CollectionHash].
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UriHashedDataMap {
    /// Hash of the entire file contents.
    ///
    /// For a ZIP, the hash must span starting from the file header to the end of the compressed file data.
    #[serde(with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub hash: Option<Vec<u8>>,

    /// Size of the file in the collection.
    ///
    /// For a ZIP, the size must span from the file header to the end of the compressed file data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    /// Mime type of the file.
    ///
    /// Note that this field is specified as `dc:format` during serialization/deserialization.
    #[serde(rename = "dc:format", skip_serializing_if = "Option::is_none")]
    pub dc_format: Option<String>,

    /// Additional information about the type of data in the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_types: Option<Vec<AssetType>>,
}

impl CollectionHash {
    pub const LABEL: &'static str = COLLECTION_HASH;

    /// Create a new, empty collection hash that hashes with the given algorithm.
    ///
    /// The base path (the root that URIs are resolved against when hashing) is supplied to
    /// [`gen_hash`](Self::gen_hash) and [`verify_hash`](Self::verify_hash).
    pub fn new(alg: String) -> Self {
        Self {
            uris: HashMap::new(),
            alg,
            zip_central_directory_hash: None,
        }
    }

    /// Adds a new file to the collection hash.
    ///
    /// The specified path MUST be a file, not a directory.
    pub fn add_file(&mut self, path: PathBuf) -> Result<()> {
        if !path.is_file() {
            return Err(Error::BadParam(format!(
                "collection hashes must only contain files, got `{}`",
                path.display()
            )));
        }

        for component in path.components() {
            match component {
                Component::CurDir | Component::ParentDir => {
                    return Err(Error::BadParam(format!(
                        "URI `{}` must not contain relative components: `.` nor `..`",
                        path.display()
                    )));
                }
                _ => {}
            }
        }

        let format = mime::mime_from_path(&path);
        let metadata = fs::metadata(&path)?;
        self.uris.insert(
            path,
            UriHashedDataMap {
                hash: None,
                size: Some(metadata.len()),
                dc_format: format,
                data_types: None,
            },
        );

        Ok(())
    }

    /// Generate the hashes for the files in the collection.
    ///
    /// The base path is the directory that each URI is resolved against.
    pub fn gen_hash(&mut self, base_path: &Path) -> Result<()> {
        if base_path.is_file() {
            return Err(Error::BadParam(format!(
                "base path must be a directory, got `{}`",
                base_path.display()
            )));
        }

        for (uri, uri_map) in &mut self.uris {
            Self::validate_uri(uri)?;

            let mut file = File::open(base_path.join(uri)).map_err(|err| match err.kind() {
                io::ErrorKind::NotFound => {
                    Error::C2PAValidation(ASSERTION_COLLECTIONHASH_INCORRECT_FILE_COUNT.to_string())
                }
                _ => Error::IoError(err),
            })?;
            let file_len = match uri_map.size {
                Some(file_len) => file_len,
                None => file.metadata()?.len(),
            };
            uri_map.hash = Some(hash_stream_by_alg(
                &self.alg,
                &mut file,
                Some(vec![HashRange::new(0, file_len)]),
                false,
            )?);
        }

        Ok(())
    }

    /// Validate the hashes for the files in the collection.
    ///
    /// The base path is the directory that each URI is resolved against.
    pub fn verify_hash(&self, base_path: &Path) -> Result<()> {
        if base_path.is_file() {
            return Err(Error::BadParam(format!(
                "base path must be a directory, got `{}`",
                base_path.display()
            )));
        }

        for (uri, uri_map) in &self.uris {
            let hash = uri_map.hash.as_ref().ok_or_else(|| {
                Error::C2PAValidation(ASSERTION_COLLECTIONHASH_MALFORMED.to_string())
            })?;

            Self::validate_uri(uri)?;

            let mut file = File::open(base_path.join(uri)).map_err(|err| match err.kind() {
                io::ErrorKind::NotFound => {
                    Error::C2PAValidation(ASSERTION_COLLECTIONHASH_INCORRECT_FILE_COUNT.to_string())
                }
                _ => Error::IoError(err),
            })?;
            let file_len = file.metadata()?.len();

            if !verify_stream_by_alg(
                &self.alg,
                hash,
                &mut file,
                Some(vec![HashRange::new(0, file_len)]),
                false,
            ) {
                return Err(Error::HashMismatch(format!(
                    "hash for {} does not match",
                    uri.display()
                )));
            }
        }

        Ok(())
    }

    /// Generate the collection hash for a ZIP-based asset.
    pub fn gen_hash_from_zip_stream<R>(&mut self, stream: &mut R) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        let zip_central_directory_inclusions = zip_central_directory_range(stream)?;
        let zip_central_directory_hash = hash_stream_by_alg(
            &self.alg,
            stream,
            Some(zip_central_directory_inclusions),
            false,
        )?;
        self.zip_central_directory_hash = Some(zip_central_directory_hash);

        self.uris = HashMap::new();
        for (path, hash_range) in zip_uri_ranges(stream)? {
            let hash =
                hash_stream_by_alg(&self.alg, stream, Some(vec![hash_range.clone()]), false)?;

            let format = mime::mime_from_path(&path);
            self.uris.insert(
                path,
                UriHashedDataMap {
                    hash: Some(hash),
                    size: Some(hash_range.length()),
                    dc_format: format,
                    data_types: None,
                },
            );
        }

        Ok(())
    }

    /// Verify the collection hash for a ZIP-based asset.
    pub fn verify_zip_stream_hash<R>(&self, stream: &mut R, alg: Option<&str>) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        let alg = alg.unwrap_or(self.alg.as_str());

        let zip_central_directory_hash = self
            .zip_central_directory_hash
            .as_ref()
            .ok_or_else(|| Error::C2PAValidation(ASSERTION_COLLECTIONHASH_MALFORMED.to_string()))?;

        let zip_central_directory_hash_range = zip_central_directory_range(stream)?;
        if !verify_stream_by_alg(
            alg,
            zip_central_directory_hash,
            stream,
            Some(zip_central_directory_hash_range),
            false,
        ) {
            return Err(Error::HashMismatch(
                "hashes do not match for ZIP central directory".to_owned(),
            ));
        }

        let uri_ranges = zip_uri_ranges(stream)?;
        for (path, uri_map) in &self.uris {
            if path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            {
                return Err(Error::C2PAValidation(
                    ASSERTION_COLLECTIONHASH_INVALID_URI.to_string(),
                ));
            }

            let hash = uri_map.hash.as_ref().ok_or_else(|| {
                Error::C2PAValidation(ASSERTION_COLLECTIONHASH_MALFORMED.to_string())
            })?;
            let hash_range = uri_ranges.get(path).cloned().ok_or_else(|| {
                Error::C2PAValidation(ASSERTION_COLLECTIONHASH_INCORRECT_FILE_COUNT.to_string())
            })?;

            if !verify_stream_by_alg(alg, hash, stream, Some(vec![hash_range]), false) {
                return Err(Error::HashMismatch(format!(
                    "hash for {} does not match",
                    path.display()
                )));
            }
        }

        Ok(())
    }

    /// Validates a collection URI per the C2PA spec.
    fn validate_uri(uri: &Path) -> Result<()> {
        if uri
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(Error::C2PAValidation(
                ASSERTION_COLLECTIONHASH_INVALID_URI.to_string(),
            ));
        }

        Ok(())
    }
}

impl AssertionBase for CollectionHash {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }
}

impl AssertionCbor for CollectionHash {}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use tempfile::TempDir;

    use super::*;

    const ZIP_SAMPLE1: &[u8] = include_bytes!("../../tests/fixtures/sample1.zip");

    fn gen_zip_collection_hash() -> Result<CollectionHash> {
        let mut stream = Cursor::new(ZIP_SAMPLE1);
        let mut collection = CollectionHash::new("sha256".to_owned());
        collection.gen_hash_from_zip_stream(&mut stream)?;

        Ok(collection)
    }

    fn gen_dir_collection_hash() -> Result<(TempDir, CollectionHash)> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("a.txt"), b"hello")?;
        fs::create_dir(dir.path().join("sub"))?;
        fs::write(dir.path().join("sub").join("b.txt"), b"world")?;

        let mut collection = CollectionHash::new("sha256".to_owned());
        for uri in ["a.txt", "sub/b.txt"] {
            collection.uris.insert(
                PathBuf::from(uri),
                UriHashedDataMap {
                    hash: None,
                    size: None,
                    dc_format: None,
                    data_types: None,
                },
            );
        }
        collection.gen_hash(dir.path())?;

        Ok((dir, collection))
    }

    #[test]
    fn test_verify_zip_stream_hash_roundtrip() -> Result<()> {
        let collection = gen_zip_collection_hash()?;
        let restored = CollectionHash::from_assertion(&collection.to_assertion()?)?;

        let mut stream = Cursor::new(ZIP_SAMPLE1);
        restored.verify_zip_stream_hash(&mut stream, None)?;

        Ok(())
    }

    #[test]
    fn test_verify_zip_stream_hash_mismatch() -> Result<()> {
        let mut collection = gen_zip_collection_hash()?;
        if let Some(entry) = collection.uris.values_mut().next() {
            entry.hash = Some(vec![0; 32]);
        }

        let mut stream = Cursor::new(ZIP_SAMPLE1);
        assert!(matches!(
            collection.verify_zip_stream_hash(&mut stream, None),
            Err(Error::HashMismatch(_))
        ));

        Ok(())
    }

    #[test]
    fn test_verify_zip_missing_central_directory_hash_is_malformed() -> Result<()> {
        let mut collection = gen_zip_collection_hash()?;
        collection.zip_central_directory_hash = None;

        let mut stream = Cursor::new(ZIP_SAMPLE1);
        assert!(matches!(
            collection.verify_zip_stream_hash(&mut stream, None),
            Err(Error::C2PAValidation(code)) if code == ASSERTION_COLLECTIONHASH_MALFORMED
        ));

        Ok(())
    }

    #[test]
    fn test_verify_zip_invalid_uri() -> Result<()> {
        let mut collection = gen_zip_collection_hash()?;
        collection.uris.insert(
            PathBuf::from("../evil.txt"),
            UriHashedDataMap {
                hash: Some(vec![0; 32]),
                size: Some(0),
                dc_format: None,
                data_types: None,
            },
        );

        let mut stream = Cursor::new(ZIP_SAMPLE1);
        assert!(matches!(
            collection.verify_zip_stream_hash(&mut stream, None),
            Err(Error::C2PAValidation(code)) if code == ASSERTION_COLLECTIONHASH_INVALID_URI
        ));

        Ok(())
    }

    #[test]
    fn test_verify_zip_incorrect_file_count() -> Result<()> {
        let mut collection = gen_zip_collection_hash()?;
        collection.uris.insert(
            PathBuf::from("sample1/not_in_zip.txt"),
            UriHashedDataMap {
                hash: Some(vec![0; 32]),
                size: Some(0),
                dc_format: None,
                data_types: None,
            },
        );

        let mut stream = Cursor::new(ZIP_SAMPLE1);
        assert!(matches!(
            collection.verify_zip_stream_hash(&mut stream, None),
            Err(Error::C2PAValidation(code)) if code == ASSERTION_COLLECTIONHASH_INCORRECT_FILE_COUNT
        ));

        Ok(())
    }

    #[test]
    fn test_directory_collection_roundtrip() -> Result<()> {
        let (dir, collection) = gen_dir_collection_hash()?;
        collection.verify_hash(dir.path())?;

        Ok(())
    }

    #[test]
    fn test_directory_verify_mismatch() -> Result<()> {
        let (dir, collection) = gen_dir_collection_hash()?;
        fs::write(dir.path().join("a.txt"), b"tampered")?;

        assert!(matches!(
            collection.verify_hash(dir.path()),
            Err(Error::HashMismatch(_))
        ));

        Ok(())
    }

    #[test]
    fn test_directory_verify_incorrect_file_count() -> Result<()> {
        let (dir, collection) = gen_dir_collection_hash()?;
        fs::remove_file(dir.path().join("a.txt"))?;

        assert!(matches!(
            collection.verify_hash(dir.path()),
            Err(Error::C2PAValidation(code)) if code == ASSERTION_COLLECTIONHASH_INCORRECT_FILE_COUNT
        ));

        Ok(())
    }

    #[test]
    fn test_directory_verify_missing_hash_is_malformed() -> Result<()> {
        let (dir, mut collection) = gen_dir_collection_hash()?;
        if let Some(entry) = collection.uris.values_mut().next() {
            entry.hash = None;
        }

        assert!(matches!(
            collection.verify_hash(dir.path()),
            Err(Error::C2PAValidation(code)) if code == ASSERTION_COLLECTIONHASH_MALFORMED
        ));

        Ok(())
    }

    #[test]
    fn test_base_path_must_be_a_directory() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("a.txt");
        fs::write(&file, b"hello")?;

        let mut collection = CollectionHash::new("sha256".to_owned());
        assert!(matches!(
            collection.gen_hash(&file),
            Err(Error::BadParam(_))
        ));
        assert!(matches!(
            collection.verify_hash(&file),
            Err(Error::BadParam(_))
        ));

        Ok(())
    }

    #[test]
    fn test_zip_hash() -> Result<()> {
        let mut stream = Cursor::new(ZIP_SAMPLE1);

        let mut collection = CollectionHash {
            uris: HashMap::new(),
            alg: "sha256".to_owned(),
            zip_central_directory_hash: None,
        };
        collection.gen_hash_from_zip_stream(&mut stream)?;

        assert_eq!(
            collection.zip_central_directory_hash,
            Some(vec![
                103, 27, 141, 219, 82, 200, 254, 44, 155, 221, 183, 146, 193, 94, 154, 77, 133, 93,
                148, 88, 160, 123, 224, 170, 61, 140, 13, 2, 153, 86, 225, 231
            ])
        );

        assert_eq!(
            collection.uris.get(Path::new("sample1/test1.txt")),
            Some(&UriHashedDataMap {
                hash: Some(vec![
                    39, 147, 91, 240, 68, 172, 194, 43, 70, 207, 141, 151, 141, 239, 180, 17, 170,
                    106, 248, 168, 169, 245, 207, 172, 29, 204, 80, 155, 37, 30, 186, 60
                ]),
                size: Some(47),
                dc_format: None,
                data_types: None,
            })
        );
        assert_eq!(
            collection.uris.get(Path::new("sample1/test1/test1.txt")),
            Some(&UriHashedDataMap {
                hash: Some(vec![
                    136, 103, 106, 251, 180, 19, 60, 244, 42, 171, 44, 215, 65, 252, 59, 127, 84,
                    63, 175, 25, 6, 118, 200, 12, 188, 128, 67, 78, 249, 182, 242, 156
                ]),
                size: Some(57),
                dc_format: None,
                data_types: None,
            })
        );
        assert_eq!(
            collection.uris.get(Path::new("sample1/test1/test2.txt")),
            Some(&UriHashedDataMap {
                hash: Some(vec![
                    164, 100, 0, 41, 229, 201, 3, 228, 30, 254, 72, 205, 60, 70, 104, 78, 121, 21,
                    187, 230, 19, 242, 52, 212, 181, 104, 99, 179, 177, 81, 150, 33
                ]),
                size: Some(53),
                dc_format: None,
                data_types: None,
            })
        );
        assert_eq!(
            collection.uris.get(Path::new("sample1/test1/test3.txt")),
            Some(&UriHashedDataMap {
                hash: Some(vec![
                    129, 96, 58, 105, 119, 67, 2, 71, 77, 151, 99, 201, 192, 32, 213, 77, 19, 22,
                    106, 204, 158, 142, 176, 247, 251, 174, 145, 243, 12, 22, 151, 116
                ]),
                size: Some(68),
                dc_format: None,
                data_types: None,
            })
        );
        assert_eq!(
            collection.uris.get(Path::new("sample1/test2.txt")),
            Some(&UriHashedDataMap {
                hash: Some(vec![
                    118, 254, 231, 173, 246, 184, 45, 104, 69, 72, 23, 21, 177, 202, 184, 241, 162,
                    36, 28, 55, 23, 62, 109, 143, 182, 233, 99, 144, 23, 139, 9, 118
                ]),
                size: Some(56),
                dc_format: None,
                data_types: None,
            })
        );
        assert_eq!(collection.uris.len(), 5);

        Ok(())
    }
}
