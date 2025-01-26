// Copyright 2024 Adobe. All rights reserved.
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

/// A `ValidationError` describes an error that was found when validating a C2PA manifest.
pub trait ValidationError {
    /// Returns the C2PA validation code for the error condition.
    /// 
    /// May return `None` if the error condition is not described in the C2PA Technical Specification.
    fn validation_code(&self) -> Option<Cow<'static, str>>;

    /// Returns the JUMBF path to the location where the error condition was identified.
    /// 
    /// May return `None` if the error condition does not pertain to a specific box in the manifest store.
    fn jumbf_path(&self) -> Option<Cow<'static, str>>;
}
