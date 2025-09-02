// Copyright 2025 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use std::{
    error,
    fs::File,
    io::{Cursor, Read, Seek},
    path::{Path, PathBuf},
};

use http::{header, Request};

use crate::{
    assertions::{labels, AssetType, EmbeddedData},
    asset_io::CAIRead,
    claim::Claim,
    definitions::ResourceDefinition,
    http::SyncHttpResolver,
    salt::DefaultSalt,
    utils::mime,
    HashedUri, Result, SigningAlg,
};

// TODO: also AsyncResolver
pub trait Resolver {
    type Error: error::Error;
    type Stream: Read + Seek + Send;

    // TODO: id can be absolutely anything, a URL, a path, a relative path, an internal proprietary identifier, etc.
    fn resolve(
        &self,
        resource_definition: ResourceDefinition,
    ) -> Result<Resource<Self::Stream>, Self::Error>;
}

pub trait PathResolver {
    type Error: error::Error;
    type Stream: Read + Seek + Send;

    fn path_resolve(&self, path: &Path) -> Result<Resource<Self::Stream>, Self::Error>;
}

// This is used internally for resolving resources in a claim to a hashed uri.
pub(crate) trait ResourceResolver {
    type Error: error::Error;

    fn resource_resolve<T>(
        &self,
        claim: &mut Claim,
        resource: Resource<T>,
    ) -> Result<HashedUri, Self::Error>
    where
        T: Read + Seek + Send;
}

impl<R: Resolver> ResourceResolver for R {
    type Error = crate::Error;

    fn resource_resolve<T>(
        &self,
        claim: &mut Claim,
        mut resource: Resource<T>,
    ) -> Result<HashedUri, Self::Error>
    where
        T: Read + Seek + Send,
    {
        let mut data = Vec::new();
        resource.read_to_end(&mut data)?;

        // TODO: pass through alg, hash, and data types
        let hashed_uri = match claim.version() {
            1 => claim.add_databox(&resource.format, data, resource.data_types)?,
            _ => {
                let icon_assertion =
                    EmbeddedData::new(labels::ICON, mime::format_to_mime(&resource.format), data);
                claim.add_assertion_with_salt(&icon_assertion, &DefaultSalt::default())?
            }
        };
        Ok(hashed_uri)
    }
}

#[derive(Debug)]
pub struct Resource<T> {
    pub stream: T,
    pub format: String,
    pub name: Option<String>,
    pub data_types: Option<Vec<AssetType>>,
    pub alg: Option<SigningAlg>,
    pub hash: Option<Vec<u8>>,
}

impl<U> Resource<U>
where
    U: Read + Seek + Send,
{
    pub fn new(format: String, stream: U) -> Self {
        Resource {
            stream,
            format,
            name: None,
            data_types: None,
            alg: None,
            hash: None,
        }
    }

    pub fn from_definition(definition: ResourceDefinition, format: String, stream: U) -> Self {
        Resource {
            stream,
            format,
            name: definition.name,
            data_types: definition.data_types,
            alg: definition.alg,
            hash: definition.hash.map(|hash| hash.into_bytes()),
        }
    }

    pub fn resolve<T: Resolver>(self, resolver: &T, claim: &mut Claim) -> Result<HashedUri> {
        // TODO: handle
        resolver.resource_resolve(claim, self)
    }

    pub fn read_to_vec(&mut self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.stream.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

impl<T: Read> Read for Resource<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl<T: Seek> Seek for Resource<T> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.stream.seek(pos)
    }
}

#[derive(Debug)]
pub struct GenericResolver {
    // http_resolver: reqwest::blocking::Client,
    http_resolver: ureq::Agent,
    base_path: Option<PathBuf>,
}

impl GenericResolver {
    pub fn new() -> Self {
        GenericResolver {
            // http_resolver: reqwest::blocking::Client::new(),
            http_resolver: ureq::agent(),
            base_path: None,
        }
    }

    pub fn set_base_path(&mut self, base_path: PathBuf) {
        self.base_path = Some(base_path);
    }
}

impl Default for GenericResolver {
    fn default() -> Self {
        GenericResolver::new()
    }
}

impl SyncHttpResolver for GenericResolver {
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<http::Response<Box<dyn Read>>, crate::http::HttpResolverError> {
        self.http_resolver.http_resolve(request)
    }
}

impl PathResolver for GenericResolver {
    type Error = crate::Error;
    type Stream = File;

    fn path_resolve(&self, path: &Path) -> Result<Resource<Self::Stream>, Self::Error> {
        let path = match &self.base_path {
            Some(base_path) => &base_path.join(path),
            None => path,
        };

        // TODO: handle unwrap
        #[allow(clippy::unwrap_used)]
        Ok(Resource::new(
            crate::format_from_path(path).unwrap(),
            File::open(path)?,
        ))
    }
}

impl Resolver for GenericResolver {
    type Error = crate::Error;
    // TODO: we don't have to box this, we can make an enum
    type Stream = Box<dyn CAIRead>;

    // TODO: remove this allow
    #[allow(clippy::unwrap_used)]
    fn resolve(
        &self,
        definition: ResourceDefinition,
    ) -> Result<Resource<Self::Stream>, Self::Error> {
        if let Ok(uri) = definition.identifier.parse::<http::Uri>() {
            // Only if it's an absolute HTTP/S URI.
            if uri.scheme().is_some() {
                let host = uri.host().map(|host| host.to_owned());
                let response = self
                    .http_resolve(Request::builder().uri(uri).body(Vec::new()).unwrap())
                    .unwrap();

                let format = response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned();

                let len = response
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .and_then(|content_length| content_length.to_str().ok())
                    .and_then(|content_length| content_length.parse().ok())
                    .unwrap_or(10000);

                let mut bytes = Vec::with_capacity(len);
                response
                    .into_body()
                    .take(1000000)
                    .read_to_end(&mut bytes)
                    .ok()
                    .unwrap();

                let mut resource: Resource<Box<dyn CAIRead>> =
                    Resource::from_definition(definition, format, Box::new(Cursor::new(bytes)));
                if resource.name.is_none() {
                    resource.name = host;
                }

                return Ok(resource);
            }
        }

        if let Ok(path) = definition.identifier.parse::<PathBuf>() {
            // TODO: handle
            #[allow(clippy::unwrap_used)]
            let stream = self.path_resolve(&path).unwrap();

            let mut resource: Resource<Box<dyn CAIRead>> =
                Resource::from_definition(definition, stream.format, Box::new(stream.stream));
            if resource.name.is_none() {
                resource.name = path
                    .file_name()
                    .map(|file_name| file_name.to_string_lossy().into_owned());
            }

            return Ok(resource);
        }

        // TODO: error, unknown identifier
        todo!()
    }
}
