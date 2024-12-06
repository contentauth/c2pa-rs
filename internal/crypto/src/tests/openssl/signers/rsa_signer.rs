use openssl::x509::X509;

use crate::{
    openssl::{signers::signer_from_cert_chain_and_private_key, validators::RsaValidator},
    raw_signature::RawSignatureValidator,
    SigningAlg,
};

#[test]
fn ps256() {
    let cert_chain = include_bytes!("../../fixtures/raw_signature/ps256.pub");
    let private_key = include_bytes!("../../fixtures/raw_signature/ps256.priv");

    let signer =
        signer_from_cert_chain_and_private_key(cert_chain, private_key, SigningAlg::Ps256, None)
            .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let cert = X509::from_pem(cert_chain).unwrap();
    let pub_key = cert.public_key().unwrap();
    let pub_key = pub_key.public_key_to_der().unwrap();

    RsaValidator::Ps256
        .validate(&signature, data, &pub_key)
        .unwrap();
}

#[test]
fn ps384() {
    let cert_chain = include_bytes!("../../fixtures/raw_signature/ps384.pub");
    let private_key = include_bytes!("../../fixtures/raw_signature/ps384.priv");

    let signer =
        signer_from_cert_chain_and_private_key(cert_chain, private_key, SigningAlg::Ps384, None)
            .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let cert = X509::from_pem(cert_chain).unwrap();
    let pub_key = cert.public_key().unwrap();
    let pub_key = pub_key.public_key_to_der().unwrap();

    RsaValidator::Ps384
        .validate(&signature, data, &pub_key)
        .unwrap();
}

#[test]
fn ps512() {
    let cert_chain = include_bytes!("../../fixtures/raw_signature/ps512.pub");
    let private_key = include_bytes!("../../fixtures/raw_signature/ps512.priv");

    let signer =
        signer_from_cert_chain_and_private_key(cert_chain, private_key, SigningAlg::Ps512, None)
            .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let cert = X509::from_pem(cert_chain).unwrap();
    let pub_key = cert.public_key().unwrap();
    let pub_key = pub_key.public_key_to_der().unwrap();

    RsaValidator::Ps512
        .validate(&signature, data, &pub_key)
        .unwrap();
}
