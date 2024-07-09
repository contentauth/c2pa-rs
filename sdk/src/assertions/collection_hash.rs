use std::{
    fs::File,
    io::{Read, Seek},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    assertions::AssetType, asset_handlers::zip_io, hash_stream_by_alg,
    hash_utils::verify_stream_by_alg, Error, HashRange, Result,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
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

    // When parsing zips we can cache the hash ranges as well in one shot.
    #[serde(skip)]
    pub(crate) zip_inclusion: Option<HashRange>,
}

impl CollectionHash {
    pub fn new(alg: String) -> Self {
        CollectionHash {
            uris: Vec::new(),
            alg: Some(alg),
            zip_central_directory_hash: None,
        }
    }

    pub fn add_uri_map(&mut self, uri_map: UriHashedDataMap) {
        self.uris.push(uri_map);
    }

    // TODO: is it safe to assume self.uris includes the stream that's being embedded into? or should
    //       we pass it as a param?
    pub fn gen_hash<R>(&mut self, base_path: &Path) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
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

    pub fn gen_uris_from_zip_stream<R>(&mut self, stream: &mut R) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        self.uris = zip_io::uri_inclusions(stream)?;
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

        for uri_map in self.uris.iter_mut() {
            match &uri_map.zip_inclusion {
                Some(inclusion) => {
                    let hash =
                        hash_stream_by_alg(&alg, stream, Some(vec![inclusion.clone()]), false)?;
                    if hash.is_empty() {
                        return Err(Error::BadParam("could not generate data hash".to_string()));
                    }

                    uri_map.hash = hash;
                }
                None => {
                    return Err(Error::BadParam(
                        "must generate zip stream uris before generating hashes".to_owned(),
                    ))
                }
            }
        }

        Ok(())
    }

    pub fn verify_stream_hash<R>(&self, alg: Option<&str>, base_path: &Path) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
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

        // TODO: we don't need to generate new uri maps, only ranges, and we only need the ranges for the
        //       files that exist in the uri_map, or should we always do all of them?
        let uris = zip_io::uri_inclusions(stream)?;
        for (uri_map, uri_map_inclusion) in self.uris.iter().zip(uris) {
            if !verify_stream_by_alg(
                alg,
                &uri_map.hash,
                stream,
                // Safe to unwrap because zip_io::uri_inclusions guarantees this field to be valid.
                #[allow(clippy::unwrap_used)]
                Some(vec![uri_map_inclusion.zip_inclusion.unwrap()]),
                false,
            ) {
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
}
