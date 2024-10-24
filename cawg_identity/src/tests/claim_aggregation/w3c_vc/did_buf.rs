// Derived from
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/dids/core/src/did.rs
// which was published under an Apache 2.0 license.

// Subsequent modifications are subject to license from Adobe
// as follows:

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

mod new {
    use crate::claim_aggregation::w3c_vc::did::DidBuf;

    #[test]
    fn valid_dids() {
        let did = DidBuf::new("did:method:foo".to_string()).unwrap();
        let did = did.as_did();
        assert_eq!(did.method_name(), "method");
        assert_eq!(did.method_specific_id(), "foo");

        let did = DidBuf::new("did:a:b".to_string()).unwrap();
        let did = did.as_did();
        assert_eq!(did.method_name(), "a");
        assert_eq!(did.method_specific_id(), "b");

        let did = DidBuf::new("did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9".to_string()).unwrap();
        let did = did.as_did();
        assert_eq!(did.method_name(), "jwk");
        assert_eq!(did.method_specific_id(), "eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9");

        let did = DidBuf::new("did:web:example.com%3A443:u:bob".to_string()).unwrap();
        let did = did.as_did();
        assert_eq!(did.method_name(), "web");
        assert_eq!(did.method_specific_id(), "example.com%3A443:u:bob");
    }

    #[test]
    fn err_invalid_did() {
        DidBuf::new("http:a:b".to_string()).unwrap_err();
        DidBuf::new("did::b".to_string()).unwrap_err();
        DidBuf::new("did:a:".to_string()).unwrap_err();
    }
}

mod impl_serde {
    use crate::claim_aggregation::w3c_vc::did::DidBuf;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Sample {
        did: DidBuf,
    }

    const SAMPLE_WITH_DID: &str = r#"{"did":"did:method:foo"}"#;
    const SAMPLE_WITH_BAD_DID: &str = r#"{"did": "did::b"}"#;

    #[test]
    fn from_json() {
        let s: Sample = serde_json::from_str(SAMPLE_WITH_DID).unwrap();
        let did = s.did;
        let did = did.as_did();
        assert_eq!(did.method_name(), "method");
        assert_eq!(did.method_specific_id(), "foo");
    }

    #[test]
    #[should_panic]
    fn from_json_err_invalid_did() {
        let _: Sample = serde_json::from_str(SAMPLE_WITH_BAD_DID).unwrap();
    }

    #[test]
    fn to_json() {
        let s = Sample {
            did: DidBuf::new("did:method:foo".to_string()).unwrap(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(&json, SAMPLE_WITH_DID);
    }
}
