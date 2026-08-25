use std::ptr::{self, NonNull};

use objc2_core_foundation::{
    CFBoolean, CFData, CFDictionary, CFError, CFNumber, CFRetained, CFString, CFType,
};
use objc2_security::{
    errSecSuccess, kSecAttrAccessControl, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAttrApplicationTag, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate,
    kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrServer, kSecAttrTokenID,
    kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassCertificate, kSecClassKey,
    kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA256,
    kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA384,
    kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA512,
    kSecKeyAlgorithmECDSASignatureMessageX962SHA256, kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
    kSecKeyAlgorithmRSASignatureMessagePSSSHA384, kSecKeyAlgorithmRSASignatureMessagePSSSHA512,
    kSecKeyKeyClass, kSecMatchLimit, kSecMatchLimitOne, kSecPrivateKeyAttrs, kSecReturnAttributes,
    kSecReturnData, kSecReturnRef, SecAccessControl, SecAccessControlCreateFlags,
    SecAccessControlCreateWithFlags, SecIdentity, SecIdentityCopyPrivateKey, SecItemCopyMatching,
    SecKey, SecKeyAlgorithm, SecKeyCopyPublicKey, SecKeyCreateRandomKey, SecKeyOperationType,
    SecKeychainItem,
};
use x509_parser::public_key;

use crate::{
    crypto::{
        base64,
        raw_signature::{RawSignatureValidationError, RawSignerError},
    },
    Error, SigningAlg,
};

pub fn create_enclave_key(
    private_key_name: &str,
    delete_conflict: bool,
) -> Result<Vec<u8>, RawSignerError> {
    let mut output = Vec::new();
    unsafe {
        // 1. Create Keys Access Control
        let flags = SecAccessControlCreateFlags::PrivateKeyUsage
            | SecAccessControlCreateFlags::UserPresence;
        let mut error: *const CFError = ptr::null();
        let access_control = SecAccessControl::with_flags(
            None,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly.as_ref(),
            flags,
            &mut error.cast_mut(),
        )
        .ok_or(RawSignerError::InternalError(
            "could not generate security access control".to_string(),
        ))?;

        // 2. Create Key Attributes
        let key_name = CFString::from_str(private_key_name);
        let ec_key_size = CFNumber::new_isize(256);

        let private_attr_dict = CFDictionary::<CFType, CFType>::from_slices(
            &[
                kSecAttrIsPermanent.as_ref(),
                kSecAttrApplicationTag.as_ref(),
                kSecAttrAccessControl.as_ref(),
            ],
            &[
                CFBoolean::new(false).as_ref(),
                key_name.as_ref(),
                access_control.as_ref(),
            ],
        );

        let attributes = CFDictionary::<CFType, CFType>::from_slices(
            &[
                kSecClass.as_ref(),
                kSecAttrKeyType.as_ref(),
                kSecAttrKeySizeInBits.as_ref(),
                kSecAttrTokenID.as_ref(),
                kSecPrivateKeyAttrs.as_ref(),
            ],
            &[
                kSecClassKey.as_ref(),
                kSecAttrKeyTypeECSECPrimeRandom.as_ref(),
                ec_key_size.as_ref(),
                kSecAttrTokenIDSecureEnclave.as_ref(),
                private_attr_dict.as_ref(),
            ],
        );

        // 3. Generate Key Pairs
        let mut error: *const CFError = ptr::null();
        let private_key = match SecKey::new_random_key(attributes.as_ref(), &mut error.cast_mut()) {
            Some(pk) => pk,
            None => {
                if let Some(e) = NonNull::new(error.cast_mut()) {
                    let desc = e.as_ref().description();
                    let code = e.as_ref().code();
                    let reason = e.as_ref().failure_reason();
                    let recovery = e.as_ref().recovery_suggestion();
                }

                return Err(RawSignerError::InternalError(format!(
                    "could not generate_key"
                )));
            }
        };

        let public_key = private_key
            .public_key()
            .ok_or(RawSignerError::InternalError(
                "could not create public key from enclave key".to_string(),
            ))?;

        let mut error: *const CFError = ptr::null();
        let public_key_bytes = public_key
            .external_representation(&mut error.cast_mut())
            .ok_or(RawSignerError::InternalError(
                "could not export public key".to_string(),
            ))?;

        let x962 = X962PublicKeyData::new(public_key_bytes.to_vec());

        output.append(&mut x962.pem().as_bytes().to_vec());
    }

    Ok(output)
}

pub fn sign_with_enclave(
    data: &[u8],
    private_key_name: &str,
    algorithm: SigningAlg,
) -> Result<Vec<u8>, RawSignerError> {
    /*
    // create a Keychain query for the desired private key
           let key_name = CFString::from_str(private_key_name);

           let dict = CFDictionary::<CFType, CFType>::from_slices(
               &[
                   kSecClass.as_ref(),
                   kSecAttrKeyClass.as_ref(),
                   kSecReturnRef.as_ref(),
                   kSecAttrLabel.as_ref(),
               ],
               &[
                   kSecClassKey.as_ref(),
                   kSecAttrKeyClassPrivate.as_ref(),
                   CFBoolean::new(true).as_ref(),
                   key_name.as_ref(),
               ],
           );

           let publicKey = SecKeyCopyPublicKey(privateKey) */

    Ok(Vec::new())
}

/// The function sign_with_keychain uses MacOS KeyChain to select a named private and
/// use it to sign the passed in bytes.  It returns the signed byes.  The function uses
/// objc2 and objc2-security crates to interact with the Keychain. SecKeyCreateSignature is used to sign the data.
/// With the private key fetched from the Keychain, and the passed in algorithm, the data is signed using the SecKeyCreateSignature function.
/// The function returns the signed data.
///
/// # Arguments
/// * `data` - The data to sign.
/// * `private_key_name` - The name of the private key to use for signing.
/// * `algorithm` - The algorithm to use for signing.
///
/// # Returns
/// The signed data.
///
/// # Errors
/// The function returns an error if the private key is not found in the Keychain or if the data cannot be signed.  The error is returned as a RawSignerError.
///
/// # Examples
/// ```rust
/// let data = b"Hello, world!";
/// let private_key_name = "my_private_key";
/// let algorithm = SigningAlg::Es256;
/// let signature = sign_with_keychain(data, private_key_name, algorithm)?;
/// println!("Signature: {:?}", signature);
/// ```    

pub fn sign_with_keychain(
    data: &[u8],
    private_key_name: &str,
    algorithm: SigningAlg,
) -> Result<Vec<u8>, RawSignerError> {
    let mut output = Vec::new();

    unsafe {
        // create a Keychain query for the desired private key
        let key_name = CFString::from_str(private_key_name);

        let dict = CFDictionary::<CFType, CFType>::from_slices(
            &[
                kSecClass.as_ref(),
                kSecAttrKeyClass.as_ref(),
                kSecReturnRef.as_ref(),
                kSecAttrLabel.as_ref(),
            ],
            &[
                kSecClassKey.as_ref(),
                kSecAttrKeyClassPrivate.as_ref(),
                CFBoolean::new(true).as_ref(),
                key_name.as_ref(),
            ],
        );

        let mut identity_item: *const CFType = ptr::null();
        let status = SecItemCopyMatching(dict.as_opaque(), &mut identity_item);
        if status != errSecSuccess {
            return Err(RawSignerError::InvalidSigningCredentials(format!(
                "Failed to find signing key {private_key_name}: {status}"
            )));
        }

        let identity_item = NonNull::new(identity_item.cast_mut())
            .map(|ptr| CFRetained::from_raw(ptr))
            .ok_or(RawSignerError::InvalidSigningCredentials(format!(
                "Failed to find signing key {private_key_name}: {status}"
            )))?;

        // convert to SecKey
        let private_key = identity_item.downcast::<SecKey>().map_err(|_e| {
            RawSignerError::InvalidSigningCredentials("could not downcast SignKey".to_string())
        })?;

        let cf_data = CFData::new(None, data.as_ptr(), data.len() as isize).ok_or(
            RawSignerError::InvalidSigningCredentials("could not create CFData".to_string()),
        )?;

        let mut error: *const CFError = ptr::null();

        let signature = private_key
            .signature(
                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                &cf_data,
                &mut error.cast_mut(),
            )
            .ok_or(RawSignerError::InvalidSigningCredentials(format!(
                "Failed to sign data: {status}"
            )))?;

        output = signature.to_vec();

        /*
                let os_algorithm = match algorithm {
                    SigningAlg::Es256 => kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA256,
                    SigningAlg::Es384 => kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA384,
                    SigningAlg::Es512 => kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA512,
                    SigningAlg::Ps256 => kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
                    SigningAlg::Ps384 => kSecKeyAlgorithmRSASignatureMessagePSSSHA384,
                    SigningAlg::Ps512 => kSecKeyAlgorithmRSASignatureMessagePSSSHA512,
                    SigningAlg::Ed25519 => return Err(Error::UnsupportedAlgorithm(algorithm)),
                };


                if !private_key.is_algorithm_supported(SecKeyOperationType::Sign, os_algorithm) {
                    return Err(RawSignerError::InvalidSigningCredentials(format!(
                        "Algorithm {algorithm} is not supported for private key {private_key_name}"
                    )));
                }

                let data = CFData::new(None, data.as_ptr(), data.len().into()?);

                let signature = private_key.signature(os_algorithm, &data, nil).map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))
                ?;

                output = signature.as_bytes_unchecked().to_vec();
        */
    }

    Ok(output)
}

pub fn verify_with_keychain(
    signature: &[u8],
    data: &[u8],
    cert_name: &str,
    algorithm: SigningAlg,
) -> Result<bool, RawSignerError> {
    let mut valid = false;

    unsafe {
        // create a Keychain query for the desired private key
        let cert_name = CFString::from_str(cert_name);

        let dict = CFDictionary::<CFType, CFType>::from_slices(
            &[
                kSecClass.as_ref(),
                kSecAttrKeyClass.as_ref(),
                kSecReturnRef.as_ref(),
                kSecAttrLabel.as_ref(),
            ],
            &[
                kSecClassKey.as_ref(),
                kSecAttrKeyClassPublic.as_ref(),
                CFBoolean::new(true).as_ref(),
                cert_name.as_ref(),
            ],
        );

        let mut identity_item: *const CFType = ptr::null();
        let status = SecItemCopyMatching(dict.as_opaque(), &mut identity_item);
        if status != errSecSuccess {
            return Err(RawSignerError::InvalidSigningCredentials(format!(
                "Failed to find signing key {cert_name}: {status}"
            )));
        }

        let identity_item = NonNull::new(identity_item.cast_mut())
            .map(|ptr| CFRetained::from_raw(ptr))
            .ok_or(RawSignerError::InvalidSigningCredentials(format!(
                "Failed to find signing key {cert_name}: {status}"
            )))?;

        // convert to SecKey
        let cert = identity_item.downcast::<SecKey>().map_err(|_e| {
            RawSignerError::InvalidSigningCredentials("could not downcast Certificate".to_string())
        })?;

        let signed_data = CFData::new(None, data.as_ptr(), data.len() as isize).ok_or(
            RawSignerError::InvalidSigningCredentials("could not create CFData".to_string()),
        )?;

        let signature = CFData::new(None, signature.as_ptr(), signature.len() as isize).ok_or(
            RawSignerError::InvalidSigningCredentials("could not create CFData".to_string()),
        )?;

        let mut error: *const CFError = ptr::null();

        valid = cert.verify_signature(
            kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
            &signed_data,
            &signature,
            &mut error.cast_mut(),
        );

        /*
                let os_algorithm = match algorithm {
                    SigningAlg::Es256 => kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA256,
                    SigningAlg::Es384 => kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA384,
                    SigningAlg::Es512 => kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA512,
                    SigningAlg::Ps256 => kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
                    SigningAlg::Ps384 => kSecKeyAlgorithmRSASignatureMessagePSSSHA384,
                    SigningAlg::Ps512 => kSecKeyAlgorithmRSASignatureMessagePSSSHA512,
                    SigningAlg::Ed25519 => return Err(Error::UnsupportedAlgorithm(algorithm)),
                };


                if !private_key.is_algorithm_supported(SecKeyOperationType::Sign, os_algorithm) {
                    return Err(RawSignerError::InvalidSigningCredentials(format!(
                        "Algorithm {algorithm} is not supported for private key {private_key_name}"
                    )));
                }

                let data = CFData::new(None, data.as_ptr(), data.len().into()?);

                let signature = private_key.signature(os_algorithm, &data, nil).map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))
                ?;

                output = signature.as_bytes_unchecked().to_vec();
        */
    }

    Ok(valid)
}

pub struct X962PublicKeyData {
    // As received from Security framework
    data: Vec<u8>,
}

impl X962PublicKeyData {
    // The open ssl compatible DER format X.509
    //
    // We take the raw key and prepend an ASN.1 headers to it. The end result is an
    // ASN.1 SubjectPublicKeyInfo structure, which is what OpenSSL is looking for.
    //
    // See the following DevForums post for more details on this.
    // https://forums.developer.apple.com/message/84684#84684
    //
    // End result looks like this
    // https://lapo.it/asn1js/#3059301306072A8648CE3D020106082A8648CE3D030107034200041F4E3F6CD8163BCC14505EBEEC9C30971098A7FA9BFD52237A3BCBBC48009162AAAFCFC871AC4579C0A180D5F207316F74088BF01A31F83E9EBDC029A533525B
    //
    pub fn der(&self) -> Vec<u8> {
        let x9_62_header_ec_header = [
            /* sequence          */ 0x30u8, 0x59, /* |-> sequence      */ 0x30, 0x13,
            /* |---> ecPublicKey */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
            0x01, // http://oid-info.com/get/1.2.840.10045.2.1 (ANSI X9.62 public key type)
            /* |---> prime256v1  */ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03,
            0x01, // http://oid-info.com/get/1.2.840.10045.3.1.7 (ANSI X9.62 named elliptic curve)
            /* |-> bit headers   */ 0x07, 0x03, 0x42, 0x00,
        ];

        let mut result = Vec::new();
        result.append(&mut x9_62_header_ec_header.to_vec());
        result.append(&mut self.data.clone());
        result
    }

    pub fn pem(&self) -> String {
        let line_len = 64;
        let mut lines = String::new();
        lines.push_str("-----BEGIN PUBLIC KEY-----\n");

        let data = base64::encode(&self.der());

        // Break line into fixed-length lines.
        let chunked_lines = data
            .chars()
            .collect::<Vec<char>>()
            .chunks(line_len)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>();

        for l in chunked_lines {
            lines.push_str(l.as_str());
            lines.push_str("\n");
        }

        lines.push_str("-----END PUBLIC KEY-----\n");

        lines
    }

    pub fn new(data: Vec<u8>) -> Self {
        X962PublicKeyData { data }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use asn1_rs::FromDer;
    use der::DecodePem;

    use crate::crypto::raw_signature::RawSignatureValidator;

    use super::*;

    #[test]
    fn generate_enclave_key() {
        let public_key_der = create_enclave_key("org.cai.devtest", true).unwrap();
        
        //pkcs8::SubjectPublicKeyInfo::from_pem(&public_key_der).unwrap();

        std::fs::write("/Users/mfisher/Downloads/se_key.der", &public_key_der).unwrap();
    }

    #[test]
    fn fetch_key() {
        let data = "this is a test";

        let signature =
            sign_with_keychain(data.as_bytes(), "C2PA_Signin_Test", SigningAlg::Es256).unwrap();
        let valid = verify_with_keychain(
            &signature,
            data.as_bytes(),
            "C2PA_Signin_Test",
            SigningAlg::Es256,
        )
        .unwrap();

        let ec_validtior =
            crate::crypto::raw_signature::rust_native::validators::EcdsaValidator::Es256;

        let signing_cert = include_bytes!("/Users/mfisher/Downloads/Certificates.der");
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(signing_cert).unwrap();
        let certificate_public_key = cert.public_key();

        let valid2 = ec_validtior
            .validate(&signature, data.as_bytes(), certificate_public_key.raw)
            .is_ok();

        assert!(valid);
        assert!(valid2);
    }
}
