use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    error::Result,
};

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
pub struct CertificateStatus(Vec<ByteBuf>);

impl CertificateStatus {
    pub const LABEL: &'static str = labels::CERTIFICATE_STATUS;

    pub fn new(ocsp_val: &[u8]) -> Self {
        let mut cs = CertificateStatus(Vec::new());
        cs.0.push(ByteBuf::from(ocsp_val.to_vec()));
        cs
    }

    pub fn add_ocsp_val(&mut self, ocsp_val: &[u8]) {
        self.0.push(ByteBuf::from(ocsp_val.to_vec()));
    }
}

impl AsRef<Vec<ByteBuf>> for CertificateStatus {
    fn as_ref(&self) -> &Vec<ByteBuf> {
        &self.0
    }
}

impl AssertionCbor for CertificateStatus {}

impl AssertionBase for CertificateStatus {
    const LABEL: &'static str = Self::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}
