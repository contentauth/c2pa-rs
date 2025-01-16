use c2pa_crypto::raw_signature::webcrypto::WindowOrWorker;
use web_sys::Crypto;

use crate::{Error, Result};

pub fn get_random_values(len: usize) -> Result<Vec<u8>> {
    let context = WindowOrWorker::new();
    let crypto: Crypto = context?.crypto()?;
    let mut values = vec![0u8; len];
    crypto
        .get_random_values_with_u8_array(&mut values)
        .map_err(|_err| Error::WasmNoCrypto)?;

    Ok(values)
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    use super::*;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_get_random_values() {
        let len: usize = 32;
        let random1 = get_random_values(len).unwrap();
        let random2 = get_random_values(len).unwrap();
        let sum_fn = |sum: u32, i: &u8| sum + (*i as u32);
        let sum1 = random1.iter().fold(0u32, sum_fn);
        let sum2 = random2.iter().fold(0u32, sum_fn);

        assert_eq!(random1.len(), len);
        assert_eq!(random2.len(), len);
        assert_ne!(sum1, sum2);
        assert!(sum1 > 0);
        assert!(sum2 > 0);
    }
}
