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
    error, fmt,
    fs::File,
    io::{Cursor, Read, Seek},
    path::PathBuf,
};

use async_trait::async_trait;

use http::{header, Request, Response};

use crate::{
    assertions::{labels, AssetType, EmbeddedData},
    asset_io::CAIRead,
    claim::Claim,
    definitions::ResourceDefinition,
    resolver::http::{
        AsyncGenericResolver, AsyncHttpResolver, HttpResolverError, SyncGenericResolver,
        SyncHttpResolver,
    },
    salt::DefaultSalt,
    utils::mime,
    HashedUri, Result, SigningAlg,
};

// TODO: also need AsyncResolver
pub trait Resolver {
    type Error: error::Error;
    type Stream: Read + Seek + Send;

    fn resolve(
        &self,
        resource_definition: ResourceDefinition,
    ) -> Result<Resource<Self::Stream>, Self::Error>;
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

pub struct GenericResolver {
    sync_http_resolver: SyncGenericResolver,
    async_http_resolver: AsyncGenericResolver,
    base_path: Option<PathBuf>,
}

impl GenericResolver {
    pub fn new() -> Self {
        GenericResolver {
            sync_http_resolver: SyncGenericResolver::new(),
            async_http_resolver: AsyncGenericResolver::new(),
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
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        self.sync_http_resolver.http_resolve(request)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncHttpResolver for GenericResolver {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        self.async_http_resolver.http_resolve_async(request).await
    }
}

impl Resolver for GenericResolver {
    type Error = crate::Error;
    // TODO: we don't have to box this, we can make an enum
    type Stream = Box<dyn CAIRead>;

    // TODO: temp
    #[allow(clippy::unwrap_used)]
    fn resolve(
        &self,
        definition: ResourceDefinition,
    ) -> Result<Resource<Self::Stream>, Self::Error> {
        if let Ok(uri) = definition.identifier.parse::<http::Uri>() {
            // Only if it's an absolute HTTP/S URI.
            if uri.scheme().is_some() {
                let host = uri.host().map(|host| host.to_owned());
                let response = self.http_resolve(Request::builder().uri(uri).body(Vec::new())?)?;

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
                response.into_body().take(1000000).read_to_end(&mut bytes)?;

                let mut resource: Resource<Box<dyn CAIRead>> =
                    Resource::from_definition(definition, format, Box::new(Cursor::new(bytes)));
                if resource.name.is_none() {
                    resource.name = host;
                }

                return Ok(resource);
            }
        }

        if let Ok(path) = definition.identifier.parse::<PathBuf>() {
            let path = match &self.base_path {
                Some(base_path) => base_path.join(path),
                None => path,
            };

            let stream = File::open(&path)?;
            let format = crate::format_from_path(&path).unwrap();

            let mut resource: Resource<Box<dyn CAIRead>> =
                Resource::from_definition(definition, format, Box::new(stream));
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

impl fmt::Debug for GenericResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    // TODO: tests
}
