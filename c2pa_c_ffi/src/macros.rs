// Copyright 2026 Adobe. All rights reserved.
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

//! Result adapters that retain the C API's published error categories.

macro_rules! ok_or_return_int {
    ($result:expr) => {
        cimpl::ok_or_return_int!(($result).map_err($crate::error::IntoCimplError::into_cimpl_error))
    };
}

macro_rules! ok_or_return_null {
    ($result:expr) => {
        cimpl::ok_or_return_null!(($result).map_err($crate::error::IntoCimplError::into_cimpl_error))
    };
}

pub(crate) use ok_or_return_int;
pub(crate) use ok_or_return_null;

#[cfg(test)]
mod tests {
    use crate::error::{C2paError, IntoCimplError};

    fn return_int<E: IntoCimplError>(result: Result<i32, E>) -> i32 {
        ok_or_return_int!(result)
    }

    fn return_null<E: IntoCimplError>(result: Result<*mut u8, E>) -> *mut u8 {
        ok_or_return_null!(result)
    }

    #[test]
    fn success_preserves_values_and_last_error() {
        cimpl::Error::other("previous error").set_last();
        assert_eq!(return_int(Ok::<_, c2pa::Error>(42)), 42);
        let mut value = 0_u8;
        let ptr = &mut value as *mut u8;
        assert_eq!(return_null(Ok::<_, c2pa::Error>(ptr)), ptr);
        assert_eq!(
            cimpl::Error::take_last().unwrap().message(),
            "Other: previous error"
        );
    }

    #[test]
    fn sdk_errors_use_published_c_categories() {
        for error in [
            c2pa::Error::RemoteManifestFetch("resolver failed".into()),
            c2pa::Error::RemoteManifestUrl("invalid URL".into()),
        ] {
            let expected = format!("Remote: {error}");
            assert_eq!(return_int(Err(error)), -1);
            assert_eq!(cimpl::Error::take_last().unwrap().message(), expected);
            assert!(expected.starts_with("Remote:"));
        }

        assert!(return_null(Err(c2pa::Error::JumbfNotFound)).is_null());
        assert!(cimpl::Error::take_last()
            .unwrap()
            .message()
            .starts_with("ManifestNotFound:"));
    }

    #[test]
    fn cimpl_errors_pass_through_unchanged() {
        let error = cimpl::Error::untracked_pointer(123);
        let expected = error.message().to_owned();
        assert_eq!(return_int(Err(error.clone())), -1);
        assert_eq!(cimpl::Error::take_last().unwrap().message(), expected);
        assert!(return_null(Err(error)).is_null());
        assert_eq!(cimpl::Error::take_last().unwrap().message(), expected);
    }

    #[test]
    fn mapped_io_and_json_errors_keep_their_prefixes() {
        assert_eq!(
            return_int(Err(C2paError::ManifestNotFound("claim: missing".into()))),
            -1
        );
        assert_eq!(
            cimpl::Error::take_last().unwrap().message(),
            "ManifestNotFound: claim: missing"
        );
        assert_eq!(return_int(Err(std::io::Error::other("read failed"))), -1);
        assert_eq!(
            cimpl::Error::take_last().unwrap().message(),
            "Io: read failed"
        );
        let error = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let expected = format!("Json: {error}");
        assert!(return_null(Err(error)).is_null());
        assert_eq!(cimpl::Error::take_last().unwrap().message(), expected);
    }
}
