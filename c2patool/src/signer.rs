// Copyright 2022 Adobe. All rights reserved.
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

use anyhow::Result;
use c2pa::{
    openssl::{EcSigner, EdSigner, RsaSigner},
    signer::ConfigurableSigner,
    signer::Signer,
};
use std::{env, path::PathBuf, process::exit};

pub fn get_ta_url() -> Option<String> {
    //const TA_URL: &str = "http://timestamp.digicert.com";
    match std::env::var("CAI_TA_URL") {
        Ok(url) => Some(url),
        Err(_) => None,
    }
}

/// Generates a temporary signature from local keys specified by the environment
/// keys can be directly in environment variables
/// or in a folder referenced by CAI_KEY_PATH
/// also supports default dev environment keys
pub fn get_test_signer() -> Result<Box<dyn Signer>> {
    // Keys can be passed in separate environment variables
    if let Ok(private_key) = env::var("CAI_PRIVATE_KEY") {
        let private_key = private_key.as_bytes().to_vec();
        if let Ok(sign_cert) = env::var("CAI_PUB_CERT") {
            let sign_cert = sign_cert.as_bytes().to_vec();
            let alg = env::var("CAI_SIGNING_ALGORITHM").ok();

            let signer: Box<dyn Signer> = match alg {
                Some(a) => match a.to_lowercase().as_str() {
                    "ps256" | "ps384" | "ps512" => Box::new(RsaSigner::from_signcert_and_pkey(
                        &sign_cert,
                        &private_key,
                        a.to_lowercase(),
                        get_ta_url(),
                    )?),
                    "es256" | "es384" | "es512" => Box::new(EcSigner::from_signcert_and_pkey(
                        &sign_cert,
                        &private_key,
                        a.to_lowercase(),
                        get_ta_url(),
                    )?),
                    "ed25519" => Box::new(EdSigner::from_signcert_and_pkey(
                        &sign_cert,
                        &private_key,
                        a.to_lowercase(),
                        get_ta_url(),
                    )?),
                    _ => {
                        eprintln!("Unsupported CAI_SIGNING_ALGORITHM, must be one of [ ps256 | ps384 | ps512 | es256 | es384 | es512 | ed25519 ]");
                        exit(2);
                    }
                },
                None => {
                    eprintln!("Must have CAI_SIGNING_ALGORITHM set");
                    exit(1);
                }
            };

            return Ok(signer);
        }
    }

    // or an environment variable can specify where to find the keys
    let key_path = match std::env::var("CAI_KEY_PATH") {
        Ok(keys_path) => PathBuf::from(keys_path),
        Err(_) => {
            // defaults to dev environment
            match env::var("CARGO_MANIFEST_DIR") {
                Ok(dir) => {
                    let mut path = PathBuf::from(dir);
                    path.push("..");
                    path.push(".x509");
                    path
                }
                Err(_) => {
                    let mut dir = dirs::home_dir().expect("home_dir");
                    dir.push(".cai");
                    dir
                }
            }
        }
    };
    // we expect the key files to be named temp_key.pem and temp_key.pub
    let mut pem_path = key_path.clone();
    pem_path.push("temp_key.pem");
    let mut pub_path = key_path;
    pub_path.push("temp_key.pub");
    if !pem_path.is_file() || !pub_path.is_file() {
        eprintln!(
        "\n\n-----------\n\n\
        Claim creation requires key files {:?} and {:?}\n\
        \n\
        You can generate a throwaway RSAPSS SSH private key for testing by \n\
        pasting the following line into a terminal and hitting enter\n\
        mkdir -p ~/.x509 ; openssl req -new -newkey rsa:4096 -sigopt rsa_padding_mode:pss -days 180 -extensions v3_ca -addext \"keyUsage = digitalSignature\" -addext \"extendedKeyUsage = emailProtection\" -nodes -x509 -keyout ~/.x509/temp_key.pem -out ~/.x509/temp_key.pub -sha256 ; sudo chmod 644 ~/.x509/temp_key.pem\n\
        \n\
        You should only need to do this once. \n\
        Set the environment var CAI_SIGNING_ALGORITHM=ps256 to set the signature algorithm 
        The environment variable CAI_KEY_PATH can specify an alternate key folder.\n\n\
        -----------\n\n"
        ,pem_path, pub_path);
        exit(1);
    }

    let alg = env::var("CAI_SIGNING_ALGORITHM")
        .unwrap_or_else(|_| "ps256".to_string())
        .to_lowercase();
    let signer: Box<dyn Signer> = match alg.as_str() {
        "ps256" | "ps384" | "ps512" => Box::new(RsaSigner::from_files(
            &pub_path,
            &pem_path,
            alg,
            get_ta_url(),
        )?),
        "es256" | "es384" | "es512" => Box::new(EcSigner::from_files(
            &pub_path,
            &pem_path,
            alg,
            get_ta_url(),
        )?),
        "ed25519" => Box::new(EdSigner::from_files(
            &pub_path,
            &pem_path,
            alg,
            get_ta_url(),
        )?),
        _ => {
            eprintln!("Unsupported CAI_SIGNING_ALGORITHM, must be one of [ ps256 | ps384 | ps512 | es256 | es384 | es512 | ed25519 ]");
            exit(1);
        }
    };

    Ok(signer)
}
