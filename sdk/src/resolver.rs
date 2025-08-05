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
    collections::HashMap,
    error,
    fs::File,
    io::{Read, Seek},
    path::{Path, PathBuf},
};

use http::{header, Request, Response};

use crate::{
    assertions::{labels, AssetType, EmbeddedData},
    asset_io::CAIRead,
    claim::Claim,
    definitions::ResourceDefinition,
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

// TODO: this
pub trait AsyncHttpResolver {
    type Error: error::Error;
    type Stream: Read + Seek + Send;

    async fn async_http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Self::Stream>, Self::Error>;
}

// SOME BACKGROUND:
// The general "Resolver" trait is just like the "ResourceResolver" trait we have in the SDK already.
// This change breaks it down into HttpResolvers/Async and PathResolvers. This enables us to use the same
// user-provided resolver struct as a way to resolve http requests, given the function constrains T: HttpResolver.
// The http implementation is feature-based #[cfg(feature="")], but also has the capability to be user defined. So,
// a resolver that implements the "Resolver" trait can propagate its identifiers to any of the underlying resolvers.
//
// Users have the ability to resolve general ids to something such as a database, something in the cloud,
// filesystem, in memory, etc. They also have the ability to define how to and how long to cache resolved ids.
pub trait HttpResolver {
    type Error: error::Error;
    type Stream: Read + Seek + Send;

    fn http_resolve_raw(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Self::Stream>, Self::Error>;

    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Resource<Self::Stream>, Self::Error> {
        let response = self.http_resolve_raw(request)?;
        // TODO: handle
        #[allow(clippy::unwrap_used)]
        let format = response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        Ok(Resource::new(format, response.into_body()))
    }
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

    cache: HashMap<String, Vec<u8>>,
    cache_enabled: bool,
}

impl GenericResolver {
    pub fn new() -> Self {
        GenericResolver {
            // http_resolver: reqwest::blocking::Client::new(),
            http_resolver: ureq::agent(),
            base_path: None,

            cache: HashMap::new(),
            cache_enabled: true,
        }
    }

    pub fn set_base_path(&mut self, base_path: PathBuf) {
        self.base_path = Some(base_path);
    }

    pub fn set_cache_enabled(&mut self, enabled: bool) {
        self.cache_enabled = enabled;
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear()
    }
}

impl Default for GenericResolver {
    fn default() -> Self {
        GenericResolver::new()
    }
}

impl HttpResolver for GenericResolver {
    type Error = crate::Error;
    // type Stream = <reqwest::blocking::Client as HttpResolver>::Stream;
    type Stream = <ureq::Agent as HttpResolver>::Stream;

    fn http_resolve_raw(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Self::Stream>, Self::Error> {
        self.http_resolver.http_resolve_raw(request)
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

    fn resolve(
        &self,
        definition: ResourceDefinition,
    ) -> Result<Resource<Self::Stream>, Self::Error> {
        if let Ok(uri) = definition.identifier.parse::<http::Uri>() {
            // Only if it's an absolute HTTP/S URI.
            if uri.scheme().is_some() {
                let host = uri.host().map(|host| host.to_owned());
                // TODO: handle
                #[allow(clippy::unwrap_used)]
                let stream = self
                    .http_resolve(Request::builder().uri(uri).body(Vec::new()).unwrap())
                    .unwrap();

                let mut resource: Resource<Box<dyn CAIRead>> =
                    Resource::from_definition(definition, stream.format, Box::new(stream.stream));
                if resource.name.is_none() {
                    resource.name = host;
                }

                if self.cache_enabled {
                    // TODO: read and store
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

// #[cfg(any(feature="reqwest", feature="reqwest_blocking"))]
mod reqwest_resolver {
    use std::io::Cursor;

    use super::*;

    use bytes::Bytes;

    // #[cfg(feature="reqwest_blocking")]
    impl HttpResolver for reqwest::blocking::Client {
        type Error = crate::Error;
        type Stream = Cursor<Bytes>;

        fn http_resolve_raw(&self, request: Request<Vec<u8>>) -> Result<Response<Self::Stream>> {
            let response = self.execute(request.try_into()?)?;

            let mut builder = http::Response::builder()
                .status(response.status())
                .version(response.version());

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            Ok(builder.body(Cursor::new(response.bytes()?))?)
        }
    }

    // #[cfg(feature="reqwest")]
    impl AsyncHttpResolver for reqwest::Client {
        type Error = crate::Error;
        type Stream = Cursor<Bytes>;

        async fn async_http_resolve(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Self::Stream>, Self::Error> {
            // TODO: reqwest has a Response::bytes_stream method
            todo!()
        }
    }
}

// #[cfg(feature = "ureq")]
mod ureq_resolver {
    use std::io::Cursor;

    use super::*;

    impl HttpResolver for ureq::Agent {
        type Error = crate::Error;
        type Stream = Cursor<Vec<u8>>;

        fn http_resolve_raw(&self, request: Request<Vec<u8>>) -> Result<Response<Self::Stream>> {
            let response = self.run(request)?;
            let data = Cursor::new(response.into_body().read_to_vec()?);
            // TODO: needs to inherit other stuff from original response
            Ok(Response::new(data))
        }
    }
}

// #[cfg(feature = "curl")]
mod curl_resolver {}
