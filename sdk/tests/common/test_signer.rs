use c2pa::{CallbackSigner, SigningAlg};

const CERTS: &[u8] = include_bytes!("../../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../../tests/fixtures/certs/ed25519.pem");

pub fn test_signer() -> CallbackSigner {
    let ed_signer = |_context: *const _, data: &[u8]| ed_sign(data, PRIVATE_KEY);
    CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS)
        .set_context("test" as *const _ as *const ())
}

fn ed_sign(data: &[u8], private_key: &[u8]) -> c2pa::Result<Vec<u8>> {
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use pem::parse;

    // Parse the PEM data to get the private key
    let pem = parse(private_key).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
    // For Ed25519, the key is 32 bytes long, so we skip the first 16 bytes of the PEM data
    let key_bytes = &pem.contents()[16..];
    let signing_key =
        SigningKey::try_from(key_bytes).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
    // Sign the data
    let signature: Signature = signing_key.sign(data);

    Ok(signature.to_bytes().to_vec())
}
