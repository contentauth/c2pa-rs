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

use asn1_rs::FromDer;
use async_generic::async_generic;
use ciborium::value::Value;
use coset::{
    iana::{self, EnumI64},
    ContentType, CoseSign1, CoseSign1Builder, Header, HeaderBuilder, Label, ProtectedHeader,
    RegisteredLabel, TaggedCborSerializable,
};
use serde_bytes::ByteBuf;
use x509_parser::prelude::X509Certificate;

use super::cert_chain_from_sign1;
use crate::{
    cose::{add_sigtst_header, add_sigtst_header_async, CoseError, TimeStampStorage},
    ec_utils::{der_to_p1363, ec_curve_from_public_key_der, parse_ec_der_sig},
    raw_signature::{AsyncRawSigner, RawSigner, SigningAlg},
};

/// Given an arbitrary block of data and a [`RawSigner`] or [`AsyncRawSigner`]
/// instance, generate a COSE signature for that block of data.
///
/// Returns a byte vector that is a `Cose_Sign1` data structure.
///
/// From [§14.5, X.509 Certificates] of the C2PA Technical Specification:
///
/// > X.509 Certificates are stored as defined by [RFC 9360] (CBOR Object
/// > Signing and Encryption (COSE): Header Parameters for Carrying and
/// > Referencing X.509 Certificates). For convenience, the definition of
/// > `x5chain` is copied below.
/// >
/// > ...
/// >
/// > `x5chain`: This header parameter contains an ordered array of X.509
/// > certificates. The certificates are to be ordered starting with the
/// > certificate containing the end-entity key followed by the certificate that
/// > signed it, and so on. There is no requirement for the entire chain to be
/// > present in the element if there is reason to believe that the relying
/// > party already has, or can locate, the missing certificates. This means
/// > that the relying party is still required to do path building but that a
/// > candidate path is proposed in this header parameter.
/// >
/// > The trust mechanism MUST process any certificates in this parameter as
/// > untrusted input. The presence of a self-signed certificate in the
/// > parameter MUST NOT cause the update of the set of trust anchors without
/// > some out-of-band confirmation. As the contents of this header parameter
/// > are untrusted input, the header parameter can be in either the protected
/// > or unprotected header bucket. Sending the header parameter in the
/// > unprotected header bucket allows an intermediary to remove or add
/// > certificates.
/// >
/// > The end-entity certificate MUST be integrity protected by COSE. This can,
/// > for example, be done by sending the header parameter in the protected
/// > header, sending an `x5chain` in the unprotected header combined with an
/// > `x5t` in the protected header, or including the end-entity certificate in
/// > the `external_aad`.
/// >
/// > This header parameter allows for a single X.509 certificate or a chain of
/// > X.509 certificates to be carried in the message.
/// >
/// > * If a single certificate is conveyed, it is placed in a CBOR byte string.
/// > * If multiple certificates are conveyed, a CBOR array of byte strings is
/// > used, with each certificate being in its own byte string.
///
/// [§14.5, X.509 Certificates]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#x509_certificates
/// [RFC 9360]: https://datatracker.ietf.org/doc/html/rfc9360
#[async_generic(async_signature(
    signer: &dyn AsyncRawSigner,
    data: &[u8],
    box_size: Option<usize>,
    tss: TimeStampStorage
))]
pub fn sign(
    signer: &dyn RawSigner,
    data: &[u8],
    box_size: Option<usize>,
    tss: TimeStampStorage,
) -> Result<Vec<u8>, CoseError> {
    if _sync {
        match tss {
            TimeStampStorage::V1_sigTst => sign_v1(signer, data, box_size, tss),
            TimeStampStorage::V2_sigTst2_CTT => sign_v2(signer, data, box_size, tss),
        }
    } else {
        match tss {
            TimeStampStorage::V1_sigTst => sign_v1_async(signer, data, box_size, tss).await,
            TimeStampStorage::V2_sigTst2_CTT => sign_v2_async(signer, data, box_size, tss).await,
        }
    }
}

#[async_generic(async_signature(
    signer: &dyn AsyncRawSigner,
    data: &[u8],
    box_size: Option<usize>,
    tss: TimeStampStorage
))]
pub fn sign_v1(
    signer: &dyn RawSigner,
    data: &[u8],
    box_size: Option<usize>,
    tss: TimeStampStorage,
) -> Result<Vec<u8>, CoseError> {
    let alg = signer.alg();

    let protected_header = if _sync {
        build_protected_header(signer, alg, None)?
    } else {
        build_protected_header_async(signer, alg, None).await?
    };

    // We don't use the additional data header.
    let aad: &[u8; 0] = b"";

    // V1: Generate time stamp then sign.
    let unprotected_header = if _sync {
        build_unprotected_header(signer, data, &protected_header, tss)?
    } else {
        build_unprotected_header_async(signer, data, &protected_header, tss).await?
    };

    let sign1_builder = CoseSign1Builder::new()
        .protected(protected_header.header.clone())
        .unprotected(unprotected_header)
        .payload(data.to_vec());

    let mut sign1 = sign1_builder.build();

    let tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        sign1.protected.clone(),
        None,
        aad,
        sign1.payload.as_ref().unwrap_or(&vec![]),
    );

    let signature = if _sync {
        signer.sign(&tbs)?
    } else {
        signer.sign(tbs).await?
    };

    // Fix up signatures that may be in the wrong format.
    sign1.signature = match alg {
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => {
            if parse_ec_der_sig(&signature).is_ok() {
                // Fix up DER signature to be in P1363 format.
                let certs = cert_chain_from_sign1(&sign1)?;

                let signing_cert = certs.first().ok_or(CoseError::CborGenerationError(
                    "bad certificate chain".to_string(),
                ))?;

                let (_, cert) = X509Certificate::from_der(signing_cert).map_err(|_e| {
                    CoseError::CborGenerationError("incorrect EC signature format".to_string())
                })?;

                let certificate_public_key = cert.public_key();

                let curve = ec_curve_from_public_key_der(certificate_public_key.raw).ok_or(
                    CoseError::CborGenerationError("incorrect EC signature format".to_string()),
                )?;

                der_to_p1363(&signature, curve.p1363_sig_len())?
            } else {
                signature
            }
        }
        _ => signature,
    };

    // The payload is provided elsewhere, so we don't need to repeat it in the
    // `Cose_Sign1` structure.
    sign1.payload = None;

    pad_cose_sig(&mut sign1, box_size)
}

#[async_generic(async_signature(
    signer: &dyn AsyncRawSigner,
    data: &[u8],
    box_size: Option<usize>,
    tss: TimeStampStorage
))]
pub fn sign_v2(
    signer: &dyn RawSigner,
    data: &[u8],
    box_size: Option<usize>,
    tss: TimeStampStorage,
) -> Result<Vec<u8>, CoseError> {
    if _sync {
        sign_v2_embedded(signer, data, box_size, CosePayload::Detached, None, tss)
    } else {
        sign_v2_embedded_async(signer, data, box_size, CosePayload::Detached, None, tss).await
    }
}

/// Configure whether the COSE payload is embedded or detached.
///
/// In C2PA usage, the payload is always detached; in other usages, it may be
/// embedded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CosePayload {
    /// Remove the payload from the signature body because it is available
    /// elsewhere.
    Detached,

    /// Include the payload in the signature body because it is not available
    /// elsewhere.
    Embedded,
}

/// Given an arbitrary block of data and a [`RawSigner`] or [`AsyncRawSigner`]
/// instance, generate a COSE signature for that block of data.
///
/// The `payload` flag allows you to configure whether the payload is detached
/// (default ofor C2PA use cases) or embedded (may be useful in other
/// applications).
///
/// Returns a byte vector that is a `Cose_Sign1` data structure.
///
/// From [§14.5, X.509 Certificates] of the C2PA Technical Specification:
///
/// > X.509 Certificates are stored as defined by [RFC 9360] (CBOR Object
/// > Signing and Encryption (COSE): Header Parameters for Carrying and
/// > Referencing X.509 Certificates). For convenience, the definition of
/// > `x5chain` is copied below.
/// >
/// > ...
/// >
/// > `x5chain`: This header parameter contains an ordered array of X.509
/// > certificates. The certificates are to be ordered starting with the
/// > certificate containing the end-entity key followed by the certificate that
/// > signed it, and so on. There is no requirement for the entire chain to be
/// > present in the element if there is reason to believe that the relying
/// > party already has, or can locate, the missing certificates. This means
/// > that the relying party is still required to do path building but that a
/// > candidate path is proposed in this header parameter.
/// >
/// > The trust mechanism MUST process any certificates in this parameter as
/// > untrusted input. The presence of a self-signed certificate in the
/// > parameter MUST NOT cause the update of the set of trust anchors without
/// > some out-of-band confirmation. As the contents of this header parameter
/// > are untrusted input, the header parameter can be in either the protected
/// > or unprotected header bucket. Sending the header parameter in the
/// > unprotected header bucket allows an intermediary to remove or add
/// > certificates.
/// >
/// > The end-entity certificate MUST be integrity protected by COSE. This can,
/// > for example, be done by sending the header parameter in the protected
/// > header, sending an `x5chain` in the unprotected header combined with an
/// > `x5t` in the protected header, or including the end-entity certificate in
/// > the `external_aad`.
/// >
/// > This header parameter allows for a single X.509 certificate or a chain of
/// > X.509 certificates to be carried in the message.
/// >
/// > * If a single certificate is conveyed, it is placed in a CBOR byte string.
/// > * If multiple certificates are conveyed, a CBOR array of byte strings is
/// > used, with each certificate being in its own byte string.
///
/// [§14.5, X.509 Certificates]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#x509_certificates
/// [RFC 9360]: https://datatracker.ietf.org/doc/html/rfc9360
#[async_generic(async_signature(
    signer: &dyn AsyncRawSigner,
    data: &[u8],
    box_size: Option<usize>,
    payload: CosePayload,
    content_type: Option<ContentType>,
    tss: TimeStampStorage
))]
pub fn sign_v2_embedded(
    signer: &dyn RawSigner,
    data: &[u8],
    box_size: Option<usize>,
    payload: CosePayload,
    content_type: Option<ContentType>,
    tss: TimeStampStorage,
) -> Result<Vec<u8>, CoseError> {
    let alg = signer.alg();

    let protected_header = if _sync {
        build_protected_header(signer, alg, content_type)?
    } else {
        build_protected_header_async(signer, alg, content_type).await?
    };

    // We don't use the additional data header.
    let aad: &[u8; 0] = b"";

    // V2: Sign then generate time stamp.
    let sign1_builder = CoseSign1Builder::new()
        .protected(protected_header.header.clone())
        .payload(data.to_vec());

    let mut sign1 = sign1_builder.build();

    let tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        sign1.protected.clone(),
        None,
        aad,
        sign1.payload.as_ref().unwrap_or(&vec![]),
    );

    let signature = if _sync {
        signer.sign(&tbs)?
    } else {
        signer.sign(tbs).await?
    };

    // Fix up signatures that may be in the wrong format.
    sign1.signature = match alg {
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => {
            if parse_ec_der_sig(&signature).is_ok() {
                // Fix up DER signature to be in P1363 format.
                let certs = cert_chain_from_sign1(&sign1)?;

                let signing_cert = certs.first().ok_or(CoseError::CborGenerationError(
                    "bad certificate chain".to_string(),
                ))?;

                let (_, cert) = X509Certificate::from_der(signing_cert).map_err(|_e| {
                    CoseError::CborGenerationError("incorrect EC signature format".to_string())
                })?;

                let certificate_public_key = cert.public_key();

                let curve = ec_curve_from_public_key_der(certificate_public_key.raw).ok_or(
                    CoseError::CborGenerationError("incorrect EC signature format".to_string()),
                )?;

                der_to_p1363(&signature, curve.p1363_sig_len())?
            } else {
                signature
            }
        }
        _ => signature,
    };

    // If the payload is provided elsewhere, we don't need to repeat it in the
    // `Cose_Sign1` structure.
    if payload == CosePayload::Detached {
        sign1.payload = None;
    }

    let sig_data = ByteBuf::from(sign1.signature.clone());
    let mut sig_data_cbor: Vec<u8> = vec![];
    ciborium::into_writer(&sig_data, &mut sig_data_cbor)
        .map_err(|e| CoseError::CborGenerationError(e.to_string()))?;

    // Fill in the unprotected header with time stamp data.
    let unprotected_header = if _sync {
        build_unprotected_header(signer, &sig_data_cbor, &protected_header, tss)?
    } else {
        build_unprotected_header_async(signer, &sig_data_cbor, &protected_header, tss).await?
    };

    sign1.unprotected = unprotected_header;

    pad_cose_sig(&mut sign1, box_size)
}

#[async_generic(async_signature(signer: &dyn AsyncRawSigner, alg: SigningAlg, content_type: Option<ContentType>))]
fn build_protected_header(
    signer: &dyn RawSigner,
    alg: SigningAlg,
    content_type: Option<ContentType>,
) -> Result<ProtectedHeader, CoseError> {
    let mut protected_h = match alg {
        SigningAlg::Ps256 => HeaderBuilder::new().algorithm(iana::Algorithm::PS256),
        SigningAlg::Ps384 => HeaderBuilder::new().algorithm(iana::Algorithm::PS384),
        SigningAlg::Ps512 => HeaderBuilder::new().algorithm(iana::Algorithm::PS512),
        SigningAlg::Es256 => HeaderBuilder::new().algorithm(iana::Algorithm::ES256),
        SigningAlg::Es384 => HeaderBuilder::new().algorithm(iana::Algorithm::ES384),
        SigningAlg::Es512 => HeaderBuilder::new().algorithm(iana::Algorithm::ES512),
        SigningAlg::Ed25519 => HeaderBuilder::new().algorithm(iana::Algorithm::SHA_1), // WRONG!
    };

    let certs = signer.cert_chain()?;

    let sc_der_array_or_bytes = match certs.len() {
        1 => Value::Bytes(certs[0].clone()),
        _ => Value::Array(certs.into_iter().map(Value::Bytes).collect()),
    };

    // Add certs to protected header.
    protected_h = protected_h.value(
        iana::HeaderParameter::X5Chain.to_i64(),
        sc_der_array_or_bytes.clone(),
    );

    // Add content type to protected header.
    match content_type {
        Some(RegisteredLabel::Assigned(n)) => {
            protected_h = protected_h.content_format(n);
        }

        Some(RegisteredLabel::Text(t)) => {
            protected_h = protected_h.content_type(t);
        }

        None => {}
    }

    let protected_header = protected_h.build();
    let ph2 = ProtectedHeader {
        original_data: None,
        header: protected_header.clone(),
    };

    Ok(ph2)
}

#[async_generic(async_signature(signer: &dyn AsyncRawSigner, data: &[u8], p_header: &ProtectedHeader, tss: TimeStampStorage,))]
fn build_unprotected_header(
    signer: &dyn RawSigner,
    data: &[u8],
    p_header: &ProtectedHeader,
    tss: TimeStampStorage,
) -> Result<Header, CoseError> {
    // signed_data_from_time_stamp_response

    // TO DO: Continue with diff here ... (let maybe_cts etc)

    let unprotected_h = HeaderBuilder::new();

    let mut unprotected_h = if _sync {
        add_sigtst_header(signer, data, p_header, unprotected_h, tss)?
    } else {
        add_sigtst_header_async(signer, data, p_header, unprotected_h, tss).await?
    };

    // Set the OCSP responder response if available.
    let ocsp_val = if _sync {
        signer.ocsp_response()
    } else {
        signer.ocsp_response().await
    };

    if let Some(ocsp) = ocsp_val {
        let mut ocsp_vec: Vec<Value> = Vec::new();
        let mut r_vals: Vec<(Value, Value)> = vec![];

        ocsp_vec.push(Value::Bytes(ocsp));
        r_vals.push((Value::Text("ocspVals".to_string()), Value::Array(ocsp_vec)));

        unprotected_h = unprotected_h.text_value("rVals".to_string(), Value::Map(r_vals));
    }

    // Build complete header.
    Ok(unprotected_h.build())
}

const PAD: &str = "pad";
const PAD2: &str = "pad2";
const PAD_OFFSET: usize = 7;

// Pad the CoseSign1 structure with zeroes to match the reserved box size. There
// are some values lengths that are impossible to hit with a single padding so
// when that happens a second padding is added to change the remaining needed
// padding. The default initial guess works for almost all sizes, without the
// need for additional loops.
fn pad_cose_sig(sign1: &mut CoseSign1, end_size: Option<usize>) -> Result<Vec<u8>, CoseError> {
    let mut sign1_clone = sign1.clone();

    let cur_vec = sign1_clone
        .to_tagged_vec()
        .map_err(|e| CoseError::CborGenerationError(e.to_string()))?;

    let Some(end_size) = end_size else {
        return Ok(cur_vec);
    };

    let cur_size = cur_vec.len();
    if cur_size == end_size {
        return Ok(cur_vec);
    }

    // Check for box too small and matched size.
    if cur_size + PAD_OFFSET > end_size {
        return Err(CoseError::BoxSizeTooSmall);
    }

    // Start close to desired end size, accounting for label.
    let mut padding_found = false;
    let mut last_pad = 0;
    let mut target_guess = end_size - cur_size - PAD_OFFSET;

    loop {
        sign1_clone = sign1.clone();

        // Replace padding with new estimate.
        for header_pair in &mut sign1_clone.unprotected.rest {
            if header_pair.0 == Label::Text("pad".to_string()) {
                if let Value::Bytes(b) = &header_pair.1 {
                    last_pad = b.len();
                }
                header_pair.1 = Value::Bytes(vec![0u8; target_guess]);
                padding_found = true;
                break;
            }
        }

        // If there was no padding, add it and try again.
        if !padding_found {
            sign1_clone.unprotected.rest.push((
                Label::Text(PAD.to_string()),
                Value::Bytes(vec![0u8; target_guess]),
            ));
            return pad_cose_sig(&mut sign1_clone, Some(end_size));
        }

        // Get current CBOR vec to see if we reached target size.
        let new_cbor = sign1_clone
            .to_tagged_vec()
            .map_err(|e| CoseError::CborGenerationError(e.to_string()))?;

        match new_cbor.len() < end_size {
            true => target_guess += 1,
            false if new_cbor.len() == end_size => return Ok(new_cbor),
            false => break,
            // ^^ We could not match end_size in a single pad so break and add a second.
        }
    }

    // If we reach here, we need a new second padding object to hit exact size.
    sign1.unprotected.rest.push((
        Label::Text(PAD2.to_string()),
        Value::Bytes(vec![0u8; last_pad - 10]),
    ));

    pad_cose_sig(sign1, Some(end_size))
}
