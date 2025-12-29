use {
    js_sys::Uint8Array,
    solana_zk_sdk::encryption::{pedersen, PEDERSEN_COMMITMENT_LEN},
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

#[wasm_bindgen]
pub struct PedersenCommitment {
    pub(crate) inner: pedersen::PedersenCommitment,
}

crate::conversion::impl_inner_conversion!(PedersenCommitment, pedersen::PedersenCommitment);

#[wasm_bindgen]
impl PedersenCommitment {
    /// Creates a Pedersen commitment from a 64-bit amount and a Pedersen opening.
    #[wasm_bindgen(js_name = from)]
    pub fn with_u64(amount: u64, opening: &PedersenOpening) -> Self {
        Self {
            inner: pedersen::Pedersen::with(amount, opening),
        }
    }

    /// Deserializes a Pedersen commitment from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(uint8_array: Uint8Array) -> Result<PedersenCommitment, JsValue> {
        if uint8_array.length() as usize != PEDERSEN_COMMITMENT_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for PedersenCommitment: expected {}, got {}",
                PEDERSEN_COMMITMENT_LEN,
                uint8_array.length()
            )));
        }

        let mut bytes = [0u8; PEDERSEN_COMMITMENT_LEN];
        uint8_array.copy_to(&mut bytes);

        pedersen::PedersenCommitment::from_bytes(&bytes)
            .map(|inner| Self { inner })
            .ok_or_else(|| JsValue::from_str("Invalid bytes for PedersenCommitment"))
    }

    /// Serializes the Pedersen commitment to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

#[wasm_bindgen]
pub struct PedersenOpening {
    pub(crate) inner: pedersen::PedersenOpening,
}

crate::conversion::impl_inner_conversion!(PedersenOpening, pedersen::PedersenOpening);

#[wasm_bindgen]
impl PedersenOpening {
    /// Creates a new, random Pedersen opening.
    #[wasm_bindgen(constructor)]
    pub fn new_rand() -> Self {
        Self {
            inner: pedersen::PedersenOpening::new_rand(),
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_opening_creation() {
        let opening1 = PedersenOpening::new_rand();
        let opening2 = PedersenOpening::new_rand();

        assert_ne!(opening1.inner.as_bytes(), opening2.inner.as_bytes());
    }

    #[wasm_bindgen_test]
    fn test_commitment_creation_and_bytes_roundtrip() {
        let amount: u64 = 12345;
        let opening = PedersenOpening::new_rand();

        let commitment = PedersenCommitment::with_u64(amount, &opening);

        // Serialization
        let bytes = commitment.to_bytes();
        assert_eq!(bytes.len(), 32); // Ristretto points are 32 bytes.
        let new_commitment =
            PedersenCommitment::from_bytes(Uint8Array::from(bytes.as_slice())).unwrap();
        assert_eq!(commitment.to_bytes(), new_commitment.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_bytes_with_invalid_input() {
        let short_bytes = vec![0; 31];
        assert!(PedersenCommitment::from_bytes(Uint8Array::from(short_bytes.as_slice())).is_err());

        let long_bytes = vec![0; 33];
        assert!(PedersenCommitment::from_bytes(Uint8Array::from(long_bytes.as_slice())).is_err());

        let invalid_point_bytes = vec![0xFF; 32];
        assert!(
            PedersenCommitment::from_bytes(Uint8Array::from(invalid_point_bytes.as_slice()))
                .is_err()
        );
    }
}
