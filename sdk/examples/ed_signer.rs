use std::io::{Cursor, Seek};

use anyhow::Result;
use c2pa::{
    create_callback_signer, ManifestStore, ManifestStoreBuilder, SignerCallback, SigningAlg,
};
#[cfg(feature = "openssl")]
use openssl::{error::ErrorStack, pkey::PKey};
use serde_json::json;

const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/es256.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/es256.pem");

#[cfg(feature = "openssl")]
fn ed_sign(data: &[u8], pkey: &[u8]) -> std::result::Result<Vec<u8>, ErrorStack> {
    let pkey = PKey::private_key_from_pem(pkey)?;
    let mut signer = openssl::sign::Signer::new_without_digest(&pkey)?;
    signer.sign_oneshot_to_vec(data)
}
#[cfg(not(feature = "openssl"))]
fn ed_sign(_data: &[u8], _pkey: &[u8]) -> std::result::Result<Vec<u8>, c2pa::Error> {
    Ok(vec![])
}

struct EdSigner {}
impl SignerCallback for EdSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        ed_sign(data, PRIVATE_KEY).map_err(|e| e.into()) //.map_err(|e| c2pa::Error::OpenSslError(e))
    }
}

pub fn main() -> Result<()> {
    let ed_signer = Box::new(EdSigner {});
    let signer = create_callback_signer(SigningAlg::Ed25519, CERTS, ed_signer, None)?;

    let format = "image/jpeg";
    let mut builder = ManifestStoreBuilder::new();
    let json = json!({
        "title": "ed_sign",
        "format": format,
        "claim_generator_info": [
            {
                "name": env!("CARGO_PKG_NAME"),
                "version": env!("CARGO_PKG_VERSION")
            }
        ]
    })
    .to_string();
    builder.with_json(&json)?;

    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(format, &mut source, &mut dest, signer.as_ref())?;
    //dest.sync_all()?;
    dest.rewind()?;
    //std::fs::write("target/foo.jpg", dest)?;
    let manifest_store = ManifestStore::from_stream(format, &mut dest, true)?;
    println!("{}", manifest_store);
    Ok(())
}

// fn openssl_rsa256_sign(data: &[u8], pkey: &[u8]) -> std::result::Result<Vec<u8>, ErrorStack> {
//     let rsa = Rsa::private_key_from_pem(pkey)?;
//     // rebuild RSA keys to eliminate incompatible values
//     let n = rsa.n().to_owned()?;
//     let e = rsa.e().to_owned()?;
//     let d = rsa.d().to_owned()?;
//     let po = rsa.p();
//     let qo = rsa.q();
//     let dmp1o = rsa.dmp1();
//     let dmq1o = rsa.dmq1();
//     let iqmpo = rsa.iqmp();
//     let mut builder = RsaPrivateKeyBuilder::new(n, e, d)?;

//     if let Some(p) = po {
//         if let Some(q) = qo {
//             builder = builder
//                 .set_factors(p.to_owned()?, q.to_owned()?)?;
//         }
//     }

//     if let Some(dmp1) = dmp1o {
//         if let Some(dmq1) = dmq1o {
//             if let Some(iqmp) = iqmpo {
//                 builder = builder
//                     .set_crt_params(dmp1.to_owned()?, dmq1.to_owned()?, iqmp.to_owned()?)?;
//             }
//         }
//     }

//     let rsa = builder.build();

//     let pkey = PKey::from_rsa(rsa)?;

//     let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &pkey)?;

//     signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
//     signer.set_rsa_mgf1_md(MessageDigest::sha256())?;
//     signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;

//     signer.sign_oneshot_to_vec(data)
// }

// struct EdSigner {}

// impl c2pa::Signer for EdSigner {
//     fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
//         use openssl::{error::ErrorStack, pkey::PKey};
//         fn openssl_ed_sign(data: &[u8], pkey: &[u8]) -> std::result::Result<Vec<u8>, ErrorStack> {
//             let pkey = PKey::private_key_from_pem(pkey)?;
//             let mut signer = openssl::sign::Signer::new_without_digest(&pkey)?;
//             signer.sign_oneshot_to_vec(data)
//         }
//         openssl_ed_sign(data, PRIVATE_KEY).map_err(c2pa::Error::OpenSslError)
//     }
//     fn alg(&self) -> SigningAlg {
//         SigningAlg::Ed25519
//     }
//     fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
//         let mut pems = pem::parse_many(CERTS).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
//         Ok(pems.drain(..).map(|p| p.into_contents()).collect())
//     }
//     fn reserve_size(&self) -> usize {
//         3000
//     }
// }
