use std::io::{Read, Seek};

use serde::{Deserialize, Serialize};

use crate::{
    assertions::AssetType,
    asset_handlers::zip_io::{self, ZipHashResolver},
    hash_stream_by_alg, CAIRead, Error, HashRange, Result,
};

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

    pub fn add_uri_map(&mut self, uri_map: UriHashedDataMap) {
        self.uri_maps.push(uri_map);
    }

    pub fn gen_hash_from_stream<R, T>(&mut self, stream: &mut R, mut resolver: T) -> Result<()>
    where
        R: Read + Seek + ?Sized,
        T: UriHashResolver,
    {
        let alg = self.alg();
        for uri_map in &mut self.uri_maps {
            let inclusions = resolver.resolve(uri_map);
            let hash = hash_stream_by_alg(&alg, stream, Some(inclusions), false)?;
            if hash.is_empty() {
                return Err(Error::BadParam("could not generate data hash".to_string()));
            }

            uri_map.hash = hash;
        }

        Ok(())
    }

    pub fn gen_hash_from_zip_stream<R>(&mut self, stream: &mut R) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        let alg = self.alg();

        let zip_central_directory_inclusions = zip_io::central_directory_inclusions(stream)?;
        let zip_central_directory_hash =
            hash_stream_by_alg(&alg, stream, Some(zip_central_directory_inclusions), false)?;
        if zip_central_directory_hash.is_empty() {
            return Err(Error::BadParam("could not generate data hash".to_string()));
        }
        self.zip_central_directory_hash = Some(zip_central_directory_hash);

        let resolver = ZipHashResolver::new(stream, &self.uri_maps)?;
        self.gen_hash_from_stream(stream, resolver)?;

        Ok(())
    }

    pub fn verify_stream_hash(&self, reader: &mut dyn CAIRead, alg: Option<&str>) -> Result<()> {
        Ok(())
    }

    fn alg(&self) -> String {
        match self.alg {
            Some(ref a) => a.clone(),
            None => "sha256".to_string(),
        }
    }
}

pub trait UriHashResolver {
    fn resolve(&mut self, uri_map: &UriHashedDataMap) -> Vec<HashRange>;
}
