use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::{labels::COLLECTION_HASH, AssetType},
    hash_stream_by_alg,
    hash_utils::verify_stream_by_alg,
    Error, HashRange, Result,
};

const ASSERTION_CREATION_VERSION: usize = 1;

#[derive(Debug, Deserialize)]
pub struct RawCollectionHash {
    alg: Option<String>,
    uris: Vec<RawUriEntry>,
}

#[derive(Debug, Deserialize)]
struct RawUriEntry {
    uri: String,

    #[serde(with = "serde_bytes")]
    hash: Option<Vec<u8>>,

    size: Option<u64>,

    #[serde(rename = "dc:format")]
    dc_format: Option<String>,
}

impl From<RawCollectionHash> for CollectionHash {
    fn from(raw: RawCollectionHash) -> Self {
        let uris = raw
            .uris
            .into_iter()
            .map(|entry| {
                (
                    PathBuf::from(entry.uri),
                    UriHashedDataMap {
                        hash: entry.hash,
                        size: entry.size,
                        dc_format: entry.dc_format,
                        data_types: None,
                        zip_hash_range: None,
                    },
                )
            })
            .collect();

        CollectionHash {
            uris,
            alg: raw.alg,
            base_path: None,
            zip_central_directory_hash: None,
            zip_central_directory_hash_range: None,
        }
    }
}

/// A collection hash is used to hash multiple files within a collection (e.g. a folder or a zip file).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CollectionHash {
    // We use a hash map to avoid potential duplicates.
    //
    /// Map of file path to their metadata for the collection.
    pub uris: HashMap<PathBuf, UriHashedDataMap>,

    /// Algorithm used to hash the files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    // TODO: in c2patool, we need to redefine this field to also handle relative paths.
    //
    /// This field represents the root directory where files must be contained within. If the path is a file, it
    /// will default to using the file's parent. For more information, read [`CollectionHash::new`][CollectionHash::new].
    ///
    /// While this field is marked as optional (it is not serialized as part of the spec), it is required for computing
    /// hashes and MUST be specified.
    #[serde(skip_serializing)]
    pub base_path: Option<PathBuf>,

    /// Hash of the ZIP central directory.
    ///
    /// This field only needs to be specified if the collection hash is for a ZIP file.
    #[serde(with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub zip_central_directory_hash: Option<Vec<u8>>,

    #[serde(skip)]
    zip_central_directory_hash_range: Option<HashRange>,
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

    #[serde(skip)]
    pub zip_hash_range: Option<HashRange>,
}

impl CollectionHash {
    pub const LABEL: &'static str = COLLECTION_HASH;

    /// Create a new collection hash with the specified base path.
    ///
    /// A base path means that any path added to the collection will use the base path as the root. If the
    /// added path is outside the scope of the base path, hashing will immediately result in an error.
    ///
    /// The base path may either be a file or a directory. However, if it s a file, it will use the parent
    /// directory as the root.
    pub fn new(base_path: PathBuf) -> Result<Self> {
        Self::new_raw(base_path, None)
    }

    /// Create a new collection hash with the specified algorithm.
    ///
    /// For more details on base_path, read [`CollectionHash::new`][CollectionHash::new].
    pub fn with_alg(base_path: PathBuf, alg: String) -> Result<Self> {
        Self::new_raw(base_path, Some(alg))
    }

    /// Adds a new file to the collection hash.
    ///
    /// Note that the specified path MUST be a file, not a directory. It must also be within the scope of the
    /// base_path. Read more on base_path in [`CollectionHash::new`][CollectionHash::new].
    pub fn add_file(&mut self, path: PathBuf) -> Result<()> {
        self.add_file_raw(path, None)
    }

    /// Add a file with the specified data types.
    ///
    /// Read more on the constraints of these parameters in [`CollectionHash::add_file`][CollectionHash::add_file].
    pub fn add_file_with_data_types(
        &mut self,
        path: PathBuf,
        data_types: Vec<AssetType>,
    ) -> Result<()> {
        self.add_file_raw(path, Some(data_types))
    }

    /// Generate the hashes for the files in the collection.
    pub fn gen_hash<R>(&mut self) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        let alg = self.alg().to_owned();
        let base_path = self.base_path()?.to_owned();

        for (path, uri_map) in &mut self.uris {
            let path = base_path.join(path);
            Self::validate_path(&path)?;

            let mut file = File::open(&path)?;
            let file_len = match uri_map.size {
                Some(file_len) => file_len,
                None => file.metadata()?.len(),
            };
            uri_map.hash = Some(hash_stream_by_alg(
                &alg,
                &mut file,
                Some(vec![HashRange::new(
                    0,
                    usize::try_from(file_len).map_err(|_| {
                        Error::BadParam(format!("Value {} out of usize range", file_len))
                    })?,
                )]),
                false,
            )?);
        }

        Ok(())
    }

    /// Validate the hashes for the files in the collection.
    pub fn verify_hash<R>(&self, alg: Option<&str>) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        let alg = alg.unwrap_or_else(|| self.alg());
        let base_path = self.base_path()?;

        for (path, uri_map) in &self.uris {
            let path = base_path.join(path);
            Self::validate_path(&path)?;

            let mut file = File::open(&path)?;
            let file_len = file.metadata()?.len();

            match &uri_map.hash {
                Some(hash) => {
                    if !verify_stream_by_alg(
                        alg,
                        hash,
                        &mut file,
                        Some(vec![HashRange::new(
                            0,
                            usize::try_from(file_len).map_err(|_| {
                                Error::BadParam(format!("Value {} out of usize range", file_len))
                            })?,
                        )]),
                        false,
                    ) {
                        return Err(Error::HashMismatch(format!(
                            "hash for {} does not match",
                            path.display()
                        )));
                    }
                }
                None => {
                    return Err(Error::BadParam(
                        "Must generate hashes before verifying".to_owned(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn gen_hash_from_zip_stream<R>(&mut self, stream: &mut R) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        let alg = self.alg().to_owned();

        let zip_central_directory_inclusions = zip_central_directory_range(stream)?;
        let zip_central_directory_hash = hash_stream_by_alg(
            &alg,
            stream,
            Some(vec![zip_central_directory_inclusions.clone()]),
            false,
        )?;
        if zip_central_directory_hash.is_empty() {
            return Err(Error::BadParam("could not generate data hash".to_string()));
        }
        self.zip_central_directory_hash_range = Some(zip_central_directory_inclusions);
        self.zip_central_directory_hash = Some(zip_central_directory_hash);

        self.uris = zip_uri_ranges(stream)?;
        for uri_map in self.uris.values_mut() {
            let hash = hash_stream_by_alg(
                &alg,
                stream,
                // We always generate the zip_hash_range in zip_uri_ranges.
                #[allow(clippy::unwrap_used)]
                Some(vec![uri_map.zip_hash_range.clone().unwrap()]),
                false,
            )?;
            if hash.is_empty() {
                return Err(Error::BadParam("could not generate data hash".to_string()));
            }

            uri_map.hash = Some(hash);
        }

        Ok(())
    }

    // pub fn verify_zip_stream_hash<R>(&self, stream: &mut R, alg: Option<&str>) -> Result<()>
    // where
    //     R: Read + Seek + ?Sized,
    // {
    //     let alg = alg.unwrap_or_else(|| self.alg());
    //     let zip_central_directory_hash = match &self.zip_central_directory_hash {
    //         Some(hash) => Ok(hash),
    //         None => Err(Error::BadParam(
    //             "Missing zip central directory hash".to_owned(),
    //         )),
    //     }?;
    //     if !verify_stream_by_alg(
    //         alg,
    //         zip_central_directory_hash,
    //         stream,
    //         // If zip_central_directory_hash exists (we checked above), then this must exist.
    //         #[allow(clippy::unwrap_used)]
    //         Some(vec![self.zip_central_directory_hash_range.clone().unwrap()]),
    //         false,
    //     ) {
    //         return Err(Error::HashMismatch(
    //             "Hashes do not match for zip central directory".to_owned(),
    //         ));
    //     }

    //     for (path, uri_map) in &self.uris {
    //         match &uri_map.hash {
    //             Some(hash) => {
    //                 if !verify_stream_by_alg(
    //                     alg,
    //                     hash,
    //                     stream,
    //                     // Same reason as above.
    //                     #[allow(clippy::unwrap_used)]
    //                     Some(vec![uri_map.zip_hash_range.clone().unwrap()]),
    //                     false,
    //                 ) {
    //                     return Err(Error::HashMismatch(format!(
    //                         "hash for {} does not match",
    //                         path.display()
    //                     )));
    //                 }
    //             }
    //             None => {
    //                 return Err(Error::BadParam(
    //                     "Must generate hashes before verifying".to_owned(),
    //                 ));
    //             }
    //         }
    //     }

    //     Ok(())
    // }
    
    pub fn verify_zip_stream_hash<R>(&self, stream: &mut R, alg: Option<&str>) -> Result<()>
where
    R: Read + Seek + ?Sized,
{
    let alg = alg.unwrap_or_else(|| self.alg());

    let uris_from_stream = zip_uri_ranges(stream)?;

    for (path, uri_map_from_manifest) in &self.uris {
        if let Some(hash_to_verify) = &uri_map_from_manifest.hash {
            if let Some(uri_from_stream) = uris_from_stream.get(path) {
                let range = uri_from_stream.zip_hash_range.clone().unwrap();
                if !verify_stream_by_alg(alg, hash_to_verify, stream, Some(vec![range]), false) {
                    return Err(Error::HashMismatch(format!(
                        "hash for {} does not match",
                        path.display()
                    )));
                }
            } else {
                return Err(Error::BadParam(format!(
                    "file {} not found in zip archive for verification",
                    path.display()
                )));
            }
        }
    }

    if let Some(cd_hash_to_verify) = &self.zip_central_directory_hash {
        let cd_range = zip_central_directory_range(stream)?; 
        if !verify_stream_by_alg(alg, cd_hash_to_verify, stream, Some(vec![cd_range]), false)
        {
            return Err(Error::HashMismatch(
                "Hashes do not match for zip central directory".to_owned(),
            ));
        }
    }

    Ok(())
}
    fn new_raw(base_path: PathBuf, alg: Option<String>) -> Result<Self> {
        Ok(Self {
            uris: HashMap::new(),
            alg,
            base_path: Some(base_path),
            zip_central_directory_hash: None,
            zip_central_directory_hash_range: None,
        })
    }

    fn add_file_raw(&mut self, path: PathBuf, data_types: Option<Vec<AssetType>>) -> Result<()> {
        Self::validate_path(&path)?;

        let format = crate::format_from_path(&path);
        let metadata = fs::metadata(&path)?;
        self.uris.insert(
            path,
            UriHashedDataMap {
                hash: None,
                size: Some(metadata.len()),
                dc_format: format,
                data_types,
                zip_hash_range: None,
            },
        );

        Ok(())
    }

    fn alg(&self) -> &str {
        self.alg.as_deref().unwrap_or("sha256")
    }

    fn base_path(&self) -> Result<&Path> {
        match &self.base_path {
            Some(base_path) => match base_path.is_file() {
                true => match base_path.parent() {
                    Some(path) => Ok(path),
                    None => Err(Error::BadParam(
                        "Base path must be a directory or a file with a parent directory"
                            .to_owned(),
                    )),
                },
                false => Ok(base_path),
            },
            None => Err(Error::BadParam(
                "Must specify base path for collection hash".to_owned(),
            )),
        }
    }

    fn validate_path(path: &Path) -> Result<()> {
        if !path.is_file() {
            return Err(Error::BadParam(format!(
                "Collection hashes must only contain files; got `{}`",
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

        Ok(())
    }
}

impl AssertionBase for CollectionHash {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }

    // We don't need to check if the zip_central_directory_hash exists, because if it is a zip
    // and one of the uri maps hashes don't exist, then that means the central dir hash doesn't exist.
    fn to_assertion(&self) -> Result<Assertion> {
        if self.uris.iter().any(|(_, uri_map)| uri_map.hash.is_none()) {
            return Err(Error::BadParam(
                "No hash found, ensure gen_hash is called".to_string(),
            ));
        }

        Self::to_cbor_assertion(self)
    }
}

impl AssertionCbor for CollectionHash {}

pub fn zip_central_directory_range<R>(reader: &mut R) -> Result<HashRange>
where
    R: Read + Seek + ?Sized,
{
    let length = reader.seek(SeekFrom::End(0))?;
    let reader = ZipArchive::new(reader).map_err(|_| Error::JumbfNotFound)?;

    let start = reader.central_directory_start();
    let length = length - start;

    Ok(HashRange::new(
        usize::try_from(start)
            .map_err(|_| Error::BadParam(format!("Value {} out of usize range", start)))?,
        usize::try_from(length)
            .map_err(|_| Error::BadParam(format!("Value {} out of usize range", length)))?,
    ))
}

pub fn zip_uri_ranges<R>(stream: &mut R) -> Result<HashMap<PathBuf, UriHashedDataMap>>
where
    R: Read + Seek + ?Sized,
{
    let mut reader = ZipArchive::new(stream).map_err(|_| Error::JumbfNotFound)?;

    let mut uri_map = HashMap::new();
    let file_names: Vec<String> = reader.file_names().map(|n| n.to_owned()).collect();
    for file_name in file_names {
        let file = reader
            .by_name(&file_name)
            .map_err(|_| Error::JumbfNotFound)?;

        if !file.is_dir() {
            match file.enclosed_name() {
                Some(path) => {
                    if path != Path::new("META-INF/content_credential.c2pa") {
                        let start = file.header_start();
                        let len =
                            (file.data_start() + file.compressed_size()) - file.header_start();
                        let format = crate::format_from_path(&path);
                        uri_map.insert(
                            path,
                            UriHashedDataMap {
                                hash: Some(Vec::new()),
                                size: Some(len),
                                dc_format: format,
                                data_types: None,
                                zip_hash_range: Some(HashRange::new(
                                    usize::try_from(start).map_err(|_| {
                                        Error::BadParam(format!(
                                            "Value {} out of usize range",
                                            start
                                        ))
                                    })?,
                                    usize::try_from(len).map_err(|_| {
                                        Error::BadParam(format!("Value {} out of usize range", len))
                                    })?,
                                )),
                            },
                        );
                    }
                }
                None => {
                    return Err(Error::BadParam(format!(
                        "Invalid stored path `{}` in zip file",
                        file_name
                    )))
                }
            }
        }
    }

    Ok(uri_map)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const ZIP_SAMPLE1: &[u8] = include_bytes!("../../tests/fixtures/sample1.zip");

    #[test]
    fn test_zip_hash() -> Result<()> {
        let mut stream = Cursor::new(ZIP_SAMPLE1);

        let mut collection = CollectionHash {
            uris: HashMap::new(),
            alg: None,
            zip_central_directory_hash: None,
            base_path: None,
            zip_central_directory_hash_range: None,
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
            collection.zip_central_directory_hash_range,
            Some(HashRange::new(369, 727))
        );

        assert_eq!(
            collection.uris.get(Path::new("sample1/test1.txt")),
            Some(&UriHashedDataMap {
                hash: Some(vec![
                    39, 147, 91, 240, 68, 172, 194, 43, 70, 207, 141, 151, 141, 239, 180, 17, 170,
                    106, 248, 168, 169, 245, 207, 172, 29, 204, 80, 155, 37, 30, 186, 60
                ]),
                size: Some(47),
                dc_format: Some("txt".to_string()),
                data_types: None,
                zip_hash_range: Some(HashRange::new(44, 47))
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
                dc_format: Some("txt".to_string()),
                data_types: None,
                zip_hash_range: Some(HashRange::new(91, 57))
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
                dc_format: Some("txt".to_string()),
                data_types: None,
                zip_hash_range: Some(HashRange::new(148, 53))
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
                dc_format: Some("txt".to_string()),
                data_types: None,
                zip_hash_range: Some(HashRange::new(201, 68))
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
                dc_format: Some("txt".to_string()),
                data_types: None,
                zip_hash_range: Some(HashRange::new(313, 56))
            })
        );
        assert_eq!(collection.uris.len(), 5);

        Ok(())
    }
}