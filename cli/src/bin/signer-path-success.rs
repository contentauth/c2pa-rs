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

use std::{
    io,
    io::{Read, Write},
    path::PathBuf,
};

use clap::Parser;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Rsa, RsaPrivateKeyBuilder},
};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct ExternalSignerArgs {
    #[clap(short, long, required = true)]
    reserve_size: usize,
    /// The algorithm used to sign the manifest.
    #[clap(short, long, required = true)]
    alg: String,
    /// The path to the public key.
    #[clap(short, long, required = true)]
    sign_cert: PathBuf,
}

/// A simple program demonstrating how to write an example CLI tool that signs C2PA manifests.
fn main() -> io::Result<()> {
    let mut bytes_to_be_signed: Vec<u8> = vec![];
    // 1. Read the bytes to be signed from this process' `stdin`.
    io::stdin().read_to_end(&mut bytes_to_be_signed).unwrap();

    // We provide a few arguments to this process via CLI args as [ExternalSignerArgs].
    // These arguments can be used for logging, determining which private key should be used,
    // or determining which algorithm should be used, etc...
    let _cli = ExternalSignerArgs::parse();

    // 2. Sign the bytes using your private key.
    let signed = rsa_sign_bytes(&bytes_to_be_signed)?;

    // 3. Write the signed bytes to `stdout`.
    let _ = io::stdout().write_all(&signed);

    Ok(())
}

fn rsa_sign_bytes(buf: &[u8]) -> io::Result<Vec<u8>> {
    let pkey = include_bytes!("../../sample/ps256.pem");

    let rsa = Rsa::private_key_from_pem(pkey)?;

    // rebuild RSA keys to eliminate incompatible values
    let n = rsa.n().to_owned()?;
    let e = rsa.e().to_owned()?;
    let d = rsa.d().to_owned()?;
    let po = rsa.p();
    let qo = rsa.q();
    let dmp1o = rsa.dmp1();
    let dmq1o = rsa.dmq1();
    let iqmpo = rsa.iqmp();
    let mut builder = RsaPrivateKeyBuilder::new(n, e, d)?;

    if let Some(p) = po {
        if let Some(q) = qo {
            builder = builder.set_factors(p.to_owned()?, q.to_owned()?)?;
        }
    }

    if let Some(dmp1) = dmp1o {
        if let Some(dmq1) = dmq1o {
            if let Some(iqmp) = iqmpo {
                builder = builder
                    .set_crt_params(dmp1.to_owned()?, dmq1.to_owned()?, iqmp.to_owned()?)
                    .unwrap();
            }
        }
    }

    let new_rsa = builder.build();

    let pkey = PKey::from_rsa(new_rsa)?;

    let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?;
    signer.set_rsa_mgf1_md(MessageDigest::sha256())?;
    signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;

    Ok(signer.sign_oneshot_to_vec(buf)?)
}
