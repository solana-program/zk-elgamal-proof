use {
    solana_zk_sdk::encryption::pedersen::{Pedersen, PedersenCommitment, PedersenOpening},
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

#[wasm_bindgen(js_name = "PedersenCommitment")]
pub struct WasmPedersenCommitment {
    pub(crate) inner: PedersenCommitment,
}

crate::conversion::impl_inner_conversion!(WasmPedersenCommitment, PedersenCommitment);

#[wasm_bindgen]
impl WasmPedersenCommitment {
    /// Creates a Pedersen commitment from a 64-bit amount and a Pedersen opening.
    #[wasm_bindgen(js_name = from)]
    pub fn with_u64(amount: u64, opening: &WasmPedersenOpening) -> Self {
        Self {
            inner: Pedersen::with(amount, opening),
        }
    }

    /// Deserializes a Pedersen commitment from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmPedersenCommitment, JsValue> {
        PedersenCommitment::from_bytes(bytes)
            .map(|inner| Self { inner })
            .ok_or_else(|| JsValue::from_str("Invalid bytes for PedersenCommitment"))
    }

    /// Serializes the Pedersen commitment to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

#[wasm_bindgen(js_name = "PedersenOpening")]
pub struct WasmPedersenOpening {
    pub(crate) inner: PedersenOpening,
}

crate::conversion::impl_inner_conversion!(WasmPedersenOpening, PedersenOpening);

#[wasm_bindgen]
impl WasmPedersenOpening {
    /// Creates a new, random Pedersen opening.
    #[wasm_bindgen(constructor)]
    pub fn new_rand() -> Self {
        Self {
            inner: PedersenOpening::new_rand(),
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, wasm_bindgen_test::*};

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_opening_creation() {
        let opening1 = WasmPedersenOpening::new_rand();
        let opening2 = WasmPedersenOpening::new_rand();

        assert_ne!(opening1.inner.as_bytes(), opening2.inner.as_bytes());
    }

    #[wasm_bindgen_test]
    fn test_commitment_creation_and_bytes_roundtrip() {
        let amount: u64 = 12345;
        let opening = WasmPedersenOpening::new_rand();

        let commitment = WasmPedersenCommitment::with_u64(amount, &opening);

        // Check if the commitment matches what the zk-sdk would create.
        let expected_inner = Pedersen::with(amount, &opening.inner);
        assert_eq!(commitment.inner, expected_inner);

        // Serialization
        let bytes = commitment.to_bytes();
        assert_eq!(bytes.len(), 32); // Ristretto points are 32 bytes.
        let new_commitment = WasmPedersenCommitment::from_bytes(&bytes).unwrap();
        assert_eq!(commitment.inner, new_commitment.inner);
    }

    #[wasm_bindgen_test]
    fn test_from_bytes_with_invalid_input() {
        // Too short
        let short_bytes = vec![0; 31];
        assert!(WasmPedersenCommitment::from_bytes(&short_bytes).is_err());

        // Too long
        let long_bytes = vec![0; 33];
        assert!(WasmPedersenCommitment::from_bytes(&long_bytes).is_err());

        // Invalid input
        let invalid_point_bytes = vec![0; 32];
        assert!(WasmPedersenCommitment::from_bytes(&invalid_point_bytes).is_err());
    }
}
