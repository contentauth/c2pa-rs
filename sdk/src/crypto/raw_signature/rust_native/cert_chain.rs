use asn1_rs::{Any, BitString, DerSequence, FromDer, Sequence};
use der::{Decode, Encode};
use x509_parser::{error::PEMError, pem::Pem};

use crate::crypto::raw_signature::RawSignerError;

/// Converts a pem chain of X509 certificate bytes to DER format.
///
/// # Arguments
/// * `cert_chain` - A chain of X509 certificates in PEM format to convert
///
/// # Returns
/// A Result containing a Vec of DER-encoded certificates or an error
pub(crate) fn cert_chain_to_der(cert_chain: &[u8],) -> Result<Vec<Vec<u8>>, RawSignerError> {
    Pem::iter_from_buffer(cert_chain)
        .map(|r| match r {
            Ok(pem) => Ok(pem.contents),
            Err(e) => Err(e),
        })
        .collect::<Result<Vec<Vec<u8>>, PEMError>>()
        .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))
}