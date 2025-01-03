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

/// The `TimeStampStorage` parameter defines how [RFC 3161] time stamps are to
/// be stored in a COSE signature.
///
/// This is as defined in [§10.3.2.5.4, Storing the time-stamp], of version 2.1
/// of the C2PA Technical Specification.
///
/// [§10.3.2.5.4, Storing the time-stamp]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_storing_the_time_stamp
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
#[allow(non_camel_case_types)] // We choose to match the exact header names as used in the C2PA specification.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TimeStampStorage {
    /// v1 time-stamps _(deprecated)_ are stored in a COSE unprotected header
    /// whose label is the string `sigTst`. If present, the value of this header
    /// shall be a `tstContainer` defined by [Example 2, “CDDL for
    /// `tstContainer`”]. The content of the `TimeStampResp` structure received
    /// in reply from the TSA shall be stored as the value of the `val property
    /// of an element of `tstTokens`.
    ///
    /// [Example 2, “CDDL for `tstContainer`”]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#tstContainer-CDDL
    V1_sigTst,

    /// v2 time-stamps shall be stored in a COSE unprotected header whose label
    /// is the string `sigTst2`. When present, the value of this header shall be
    /// a `tstContainer` defined by [Example 2, “CDDL for `tstContainer`”]. The
    /// content of value of the `timeStampToken` field of the `TimeStampResp`
    /// structure received in reply from the TSA shall be stored as the value of
    /// the `val` property of an element of `tstTokens`.
    ///
    /// **NOTE:** A v2 time-stamp is equivalent to the "CTT" model of [COSE
    /// Header parameter for RFC 3161 Time-Stamp Tokens Draft]. It requires that
    /// the complete signature structure be completed prior to time-stamping,
    /// thus enabling the time-stamp to serve as a countersignature on the
    /// entire signature structure, including the actual certificate.
    ///
    /// [Example 2, “CDDL for `tstContainer`”]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#tstContainer-CDDL
    /// [COSE Header parameter for RFC 3161 Time-Stamp Tokens Draft]: https://datatracker.ietf.org/doc/draft-ietf-cose-tsa-tst-header-parameter/
    V2_sigTst2_CTT,
}
