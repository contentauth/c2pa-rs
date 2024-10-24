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

mod verified_identity_defaults {
    // Test coverage for the default causes of VerifiedIdentity trait.

    use chrono::{DateTime, FixedOffset};

    use crate::{VerifiedIdentity, VerifiedIdentityType};

    #[derive(Debug)]
    struct TestVerifiedIdentity {}

    impl VerifiedIdentity for TestVerifiedIdentity {
        fn type_(&self) -> VerifiedIdentityType {
            VerifiedIdentityType::DocumentVerification
        }

        fn verified_at(&self) -> DateTime<FixedOffset> {
            DateTime::parse_from_rfc3339("2024-09-03T18:54:24Z").unwrap()
        }
    }

    #[test]
    fn name() {
        let tvi = TestVerifiedIdentity {};
        assert!(tvi.name().is_none());
    }

    #[test]
    fn username() {
        let tvi = TestVerifiedIdentity {};
        assert!(tvi.username().is_none());
    }

    #[test]
    fn address() {
        let tvi = TestVerifiedIdentity {};
        assert!(tvi.address().is_none());
    }

    #[test]
    fn uri() {
        let tvi = TestVerifiedIdentity {};
        assert!(tvi.uri().is_none());
    }
}
