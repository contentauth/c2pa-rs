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

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

use super::test_issuer::TestIssuer;

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
async fn default_case() {
    let ti = TestIssuer::new();
    ti.test_basic_case().await;
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[should_panic] // TEMPORARY until error results are implemented
async fn error_no_issuer() {
    let ti = TestIssuer::from_asset_vc(
        r#"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "credentialSubject": {
                "id": "did:key:z6Mkmf541wxtnV7n5YAnToRw5JRHJUMQYHBzpkCzyRTHpuL8"
            }
        }"#,
    );

    ti.test_basic_case().await;
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[should_panic] // TEMPORARY until error results are implemented
async fn error_no_issuance_date() {
    let ti = TestIssuer::from_asset_vc(
        r#"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "credentialSubject": {
                "id": "did:key:z6Mkp4n6JaXdECTcy7GLsWrc2bUmSYi3nbKt5grWQznFdYKz"
            },
            "issuer": "did:key:z6MkmJhxUFcNhqWqapiPMWhCk6QjSnqRGdiUfmBdVw6Haf7G"
        }"#,
    );

    ti.test_basic_case().await;
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[should_panic] // TEMPORARY until error results are implemented
async fn error_no_proof() {
    let ti = TestIssuer::from_asset_vc(
        r#"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "credentialSubject": {
                "id": "did:key:z6Mktf2a2pRkJuiwUKPcyWSNnWMwgCoUvqtjmYfYUwiqVx3u"
            },
            "issuer": "did:key:z6MkicKWYcotCaNY2aPz6rftxr9wkj8K6JzfRhQadycEApnB",
            "issuanceDate": "2024-07-18T21:20:08Z"
        }"#,
    );

    ti.test_basic_case().await;
}

/* TEMPORARY: Holding off on this one until SSI crate handles VC V2. :-(
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[should_panic] // TEMPORARY until error results are implemented
async fn error_v1_vc() {
    let ti = TestIssuer::from_asset_vc(
        r#"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "credentialSubject": {
                "id": "did:key:z6MkuaqcTbHDF7dEYjBgpH2ZHobFXSF4Z6yrr99RVmopZSap"
            },
            "issuer": "did:key:z6Mkeh5pnxVsa5Goi4FKjKA3NPq5Ruu1geu8BX1J2sxGw8uZ",
            "issuanceDate": "2024-07-18T21:20:08Z",
            "proof": {
                "type": "Ed25519Signature2018",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:key:z6Mkeh5pnxVsa5Goi4FKjKA3NPq5Ruu1geu8BX1J2sxGw8uZ#z6Mkeh5pnxVsa5Goi4FKjKA3NPq5Ruu1geu8BX1J2sxGw8uZ",
                "created": "2024-07-18T22:35:10.956893Z",
                "jws": "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..-njhADD8Lw60cBtXY3SB9QAntpMwzqeoQH01vHPh3hKohGgSsJFwDwhlZv0cCchIhxvkofR48BxICIb8yDDDAQ"
            }
        }"#,
    );

    ti.test_basic_case().await;
}
*/

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[should_panic] // TEMPORARY until error results are implemented
async fn error_missing_cawg_context() {
    let ti = TestIssuer::from_asset_vc(
        r#"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "credentialSubject": {
                "id": "did:key:z6MkrF1rgvo8xrdNuiEEQ4wWNcGY9Y5DxHhmX47StpEpRKNP"
            },
            "issuer": "did:key:z6Mkufa8L8baH4zhPsG5g9zrC6bSYcptVxf4ZLe5tp6fN95P",
            "issuanceDate": "2024-07-18T21:20:08Z",
            "proof": {
                "type": "Ed25519Signature2018",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:key:z6Mkufa8L8baH4zhPsG5g9zrC6bSYcptVxf4ZLe5tp6fN95P#z6Mkufa8L8baH4zhPsG5g9zrC6bSYcptVxf4ZLe5tp6fN95P",
                "created": "2024-07-18T23:00:42.691817Z",
                "jws": "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..CIX3bgpS-0fdDrioNTEl4ajNpDKGRQ_t4cJNpAIZM5rSVr8EikFzLLdp6TfRPj_oCb_CunMH_pGJt7UYx8mBBA"
            }
        }"#,
    );

    ti.test_basic_case().await;
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[should_panic] // TEMPORARY until error results are implemented
async fn error_missing_cawg_type() {
    let ti = TestIssuer::from_asset_vc(
        r#"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://creator-assertions.github.io/tbd/tbd"
            ],
            "type": "VerifiableCredential",
            "credentialSubject": {
                "id": "did:key:z6MkkJiN1FEMbZ4RizjY72KHKSn5sNaXdyf49eXYXRCpGqSZ"
            },
            "issuer": "did:key:z6MkuDQroB2sPU2ZW45csYLU7yy2Z1BCpFbFf4TwJhEnFj7j",
            "issuanceDate": "2024-07-18T21:20:08Z",
            "proof": {
                "type": "Ed25519Signature2018",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:key:z6MkuDQroB2sPU2ZW45csYLU7yy2Z1BCpFbFf4TwJhEnFj7j#z6MkuDQroB2sPU2ZW45csYLU7yy2Z1BCpFbFf4TwJhEnFj7j",
                "created": "2024-07-19T01:04:33.677700Z",
                "jws": "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..Ze5lql1iCV5fyIStYt1ji2cSc8yORrqDhkk5VJDcsIAduhjqua3KDQ7BVmnm2XOW5sDomp4KSvr7kNZAQWuIDg"
            }
        }"#,
    );

    ti.test_basic_case().await;
}
