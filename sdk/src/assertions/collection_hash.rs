use std::{
    fs::{self, File},
    io::{Read, Seek},
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

// TODO: which version?
const ASSERTION_CREATION_VERSION: usize = 2;

/// A collection hash is used to hash multiple files within a collection (e.g. a folder or a zip file).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CollectionHash {
    /// List of files and their metadata to include in the collection hash.
    pub uris: Vec<UriHashedDataMap>,

    /// Algorithm used to hash the files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    // Although this isn't explicitly defined in the spec, user's MUST specify a base path when constructing
    // a collection hash. You may notice that zips do not require this field, so we can make it optional,
    // but that would mean users can optionally specify it, which isn't true.
    //
    /// This field represents the root directory where files must be contained within. If the path is a file, it
    /// will default to using the file's parent. For more information, read [`CollectionHash::new`][CollectionHash::new].
    pub base_path: PathBuf,

    // The user would never need to explicilty specify this field, it's always recomputed internally.
    #[serde(with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    zip_central_directory_hash: Option<Vec<u8>>,

    #[serde(skip)]
    zip_central_directory_hash_range: Option<HashRange>,
}

/// Information about a file in a [`CollectionHash`][CollectionHash].
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UriHashedDataMap {
    /// Path to the file included in the collection.
    pub uri: PathBuf,

    // Same as zip_central_directory_hash, this field is always recomputed, users would never need to specify it
    // explicitly.
    #[serde(with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    hash: Option<Vec<u8>>,

    /// Size of the file in the collection.
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
    zip_hash_range: Option<HashRange>,
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
    pub fn new(base_path: PathBuf) -> Self {
        Self {
            uris: Vec::new(),
            alg: None,
            // TODO: if base_path is a file, then do .parent() or error?
            base_path,
            zip_central_directory_hash: None,
            zip_central_directory_hash_range: None,
        }
    }

    /// Create a new collection hash with the specified algorithm.
    ///
    /// For more details on base_path, read [`CollectionHash::new`][CollectionHash::new].
    pub fn with_alg(base_path: PathBuf, alg: String) -> Self {
        Self {
            uris: Vec::new(),
            alg: Some(alg),
            base_path,
            zip_central_directory_hash: None,
            zip_central_directory_hash_range: None,
        }
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
        for uri_map in &mut self.uris {
            let path = &uri_map.uri;
            Self::validate_path(path)?;

            let mut file = File::open(path)?;
            let file_len = match uri_map.size {
                Some(file_len) => file_len,
                None => file.metadata()?.len(),
            };
            uri_map.hash = Some(hash_stream_by_alg(
                &alg,
                &mut file,
                // TODO: temp unwrap
                #[allow(clippy::unwrap_used)]
                Some(vec![HashRange::new(0, usize::try_from(file_len).unwrap())]),
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
        for uri_map in &self.uris {
            let path = &uri_map.uri;
            Self::validate_path(path)?;

            let mut file = File::open(path)?;
            let file_len = file.metadata()?.len();

            match &uri_map.hash {
                Some(hash) => {
                    if !verify_stream_by_alg(
                        alg,
                        hash,
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
                None => todo!(),
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
            Some(vec![zip_central_directory_inclusions]),
            false,
        )?;
        if zip_central_directory_hash.is_empty() {
            return Err(Error::BadParam("could not generate data hash".to_string()));
        }
        self.zip_central_directory_hash = Some(zip_central_directory_hash);

        self.uris = zip_uri_ranges(stream)?;
        for uri_map in &mut self.uris {
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

    pub fn verify_zip_stream_hash<R>(&self, stream: &mut R, alg: Option<&str>) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        let alg = alg.unwrap_or_else(|| self.alg());
        let zip_central_directory_hash = match &self.zip_central_directory_hash {
            Some(hash) => Ok(hash),
            None => Err(Error::BadParam(
                "Missing zip central directory hash".to_owned(),
            )),
        }?;
        if !verify_stream_by_alg(
            alg,
            zip_central_directory_hash,
            stream,
            // If zip_central_directory_hash exists (we checked above), then this must exist.
            #[allow(clippy::unwrap_used)]
            Some(vec![self.zip_central_directory_hash_range.clone().unwrap()]),
            false,
        ) {
            return Err(Error::HashMismatch(
                "Hashes do not match for zip central directory".to_owned(),
            ));
        }

        for uri_map in &self.uris {
            match &uri_map.hash {
                Some(hash) => {
                    if !verify_stream_by_alg(
                        alg,
                        hash,
                        stream,
                        // Same reason as above.
                        #[allow(clippy::unwrap_used)]
                        Some(vec![uri_map.zip_hash_range.clone().unwrap()]),
                        false,
                    ) {
                        return Err(Error::HashMismatch(format!(
                            "hash for {} does not match",
                            uri_map.uri.display()
                        )));
                    }
                }
                None => todo!(),
            }
        }

        Ok(())
    }

    fn add_file_raw(&mut self, path: PathBuf, data_types: Option<Vec<AssetType>>) -> Result<()> {
        // TODO: how should we handle if the path already exists in the collection?
        Self::validate_path(&path)?;

        let format = crate::format_from_path(&path);
        let metadata = fs::metadata(&path)?;
        self.uris.push(UriHashedDataMap {
            uri: self.base_path.join(path),
            hash: None,
            size: Some(metadata.len()),
            dc_format: format,
            data_types,
            zip_hash_range: None,
        });

        Ok(())
    }

    fn alg(&self) -> &str {
        self.alg.as_deref().unwrap_or("sha256")
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
        if self.uris.iter().any(|uri_map| uri_map.hash.is_none()) {
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
    let _reader = ZipArchive::new(reader).map_err(|_| Error::JumbfNotFound)?;

    // TODO: https://github.com/zip-rs/zip2/issues/209

    todo!()
}

pub fn zip_uri_ranges<R>(stream: &mut R) -> Result<Vec<UriHashedDataMap>>
where
    R: Read + Seek + ?Sized,
{
    let mut reader = ZipArchive::new(stream).map_err(|_| Error::JumbfNotFound)?;

    let mut uri_maps = Vec::new();
    let file_names: Vec<String> = reader.file_names().map(|n| n.to_owned()).collect();
    for file_name in file_names {
        let file = reader
            .by_name(&file_name)
            .map_err(|_| Error::JumbfNotFound)?;

        if !file.is_dir() {
            match file.enclosed_name() {
                Some(path) => {
                    if path != Path::new("META-INF/content_credential.c2pa") {
                        uri_maps.push(UriHashedDataMap {
                            dc_format: crate::format_from_path(&path),
                            uri: path,
                            hash: Some(Vec::new()),
                            size: Some(
                                (file.data_start() + file.compressed_size()) - file.header_start(),
                            ),
                            data_types: None,
                            // TODO: fix error types
                            zip_hash_range: Some(HashRange::new(
                                usize::try_from(file.header_start())
                                    .map_err(|_| Error::JumbfNotFound)?,
                                usize::try_from(
                                    (file.data_start() + file.compressed_size())
                                        - file.header_start(),
                                )
                                .map_err(|_| Error::JumbfNotFound)?,
                            )),
                        });
                    }
                }
                None => todo!(),
            }
        }
    }

    Ok(uri_maps)
}

// TODO: blocked by central_directory_inclusions
// #[cfg(test)]
// mod tests {
//     use std::io::Cursor;

//     use super::*;

//     const ZIP_SAMPLE1: &[u8] = include_bytes!("../../tests/fixtures/sample1.zip");

// #[test]
// fn test_zip_hash() -> Result<()> {
//     let mut stream = Cursor::new(ZIP_SAMPLE1);

//     let mut collection = CollectionHash {
//         uris: Vec::new(),
//         alg: None,
//         zip_central_directory_hash: None,
//         base_path: PathBuf::new(),
//         zip_central_directory_hash_range: None,
//     };
//     collection.gen_hash_from_zip_stream(&mut stream)?;

//     assert_eq!(collection.zip_central_directory_hash, vec![0]);
//     assert_eq!(
//         collection.zip_central_directory_hash_range,
//         Some(HashRange::new(0, 0))
//     );

//     assert_eq!(
//         collection.uris.first(),
//         Some(&UriHashedDataMap {
//             uri: PathBuf::from("sample1/test1.txt"),
//             hash: Some(vec![0]),
//             size: Some(47),
//             dc_format: None,
//             data_types: None,
//             zip_hash_range: None,
//         })
//     );
//     assert_eq!(
//         collection.uris.get(1),
//         Some(&UriHashedDataMap {
//             uri: PathBuf::from("sample1/test1/test1.txt"),
//             hash: Some(vec![0]),
//             size: Some(57),
//             dc_format: None,
//             data_types: None,
//             zip_hash_range: None,
//         })
//     );
//     assert_eq!(
//         collection.uris.get(2),
//         Some(&UriHashedDataMap {
//             uri: PathBuf::from("sample1/test1/test2.txt"),
//             hash: Some(vec![0]),
//             size: Some(53),
//             dc_format: None,
//             data_types: None,
//             zip_hash_range: None,
//         })
//     );
//     assert_eq!(
//         collection.uris.get(3),
//         Some(&UriHashedDataMap {
//             uri: PathBuf::from("sample1/test1/test3.txt"),
//             hash: Some(vec![0]),
//             size: Some(68),
//             dc_format: None,
//             data_types: None,
//             zip_hash_range: None,
//         })
//     );
//     assert_eq!(
//         collection.uris.get(4),
//         Some(&UriHashedDataMap {
//             uri: PathBuf::from("sample1/test2.txt"),
//             hash: Some(vec![0]),
//             size: Some(56),
//             dc_format: None,
//             data_types: None,
//             zip_hash_range: None,
//         })
//     );
//     assert_eq!(collection.uris.len(), 5);

//     Ok(())
// }
// }
