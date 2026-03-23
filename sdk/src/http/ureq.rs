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

#[cfg(all(feature = "http_ureq", not(target_arch = "wasm32")))]
pub mod sync_impl {
    use std::io::Read;

    use http::{header, Request, Response};

    use crate::http::{HttpResolverError, SyncHttpResolver};

    impl SyncHttpResolver for ureq::Agent {
        fn http_resolve(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            let response = self.run(request)?;

            let mut builder = http::Response::builder()
                .status(response.status())
                .version(response.version());

            if let Some(content_type) = response.headers().get(header::CONTENT_TYPE) {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }

            let body = response.into_body().into_reader();
            Ok(builder.body(Box::new(body) as Box<dyn Read>)?)
        }
    }

    impl From<ureq::Error> for HttpResolverError {
        fn from(value: ureq::Error) -> Self {
            Self::Other(Box::new(value))
        }
    }

    #[cfg(test)]
    pub mod tests {
        use crate::http::tests::assert_http_resolver;

        #[test]
        fn test_http_ureq() {
            assert_http_resolver(ureq::agent());
        }
    }
}
