use std::io::{Read, Seek};

use serde::{Deserialize, Serialize};

use crate::{assertions::AssetType, asset_handlers::zip_io, hash_stream_by_alg, Error, Result};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CollectionHash {
    pub uri_maps: Vec<UriHashedDataMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub zip_central_directory_hash: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UriHashedDataMap {
    pub uri: String,

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
    pub fn new(alg: String) -> Self {
        CollectionHash {
            uri_maps: Vec::new(),
            alg: Some(alg),
            zip_central_directory_hash: None,
        }
    }

    fn add_uri_map(&mut self, uri_map: UriHashedDataMap) {
        self.uri_maps.push(uri_map);
    }

    // TODO: support custom collection hashes
    pub fn gen_hash_from_stream<R>(&mut self, stream: &mut R) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        let alg = match self.alg {
            Some(ref a) => a.clone(),
            None => "sha256".to_string(),
        };

        let zip_central_directory_inclusions = zip_io::central_directory_inclusions(stream)?;
        let zip_central_directory_hash =
            hash_stream_by_alg(&alg, stream, Some(zip_central_directory_inclusions), false)?;
        if zip_central_directory_hash.is_empty() {
            return Err(Error::BadParam("could not generate data hash".to_string()));
        }
        self.zip_central_directory_hash = Some(zip_central_directory_hash);

        let uri_inclusions = zip_io::uri_inclusions(stream, &self.uri_maps)?;
        for (i, uri_map) in self.uri_maps.iter_mut().enumerate() {
            let hash =
                hash_stream_by_alg(&alg, stream, Some(vec![uri_inclusions[i].clone()]), false)?;
            if hash.is_empty() {
                return Err(Error::BadParam("could not generate data hash".to_string()));
            }

            uri_map.hash = hash;
        }

        Ok(())
    }
}
