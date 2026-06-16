use {
    js_sys::Uint8Array,
    solana_zk_sdk::encryption::pedersen,
    solana_zk_sdk_pod::encryption::PEDERSEN_COMMITMENT_LEN,
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

fn lo_hi_multiplier(bit_length: u8) -> Result<u64, JsValue> {
    1u64.checked_shl(bit_length.into())
        .ok_or_else(|| JsValue::from_str("bit length must be less than 64"))
}

#[wasm_bindgen]
pub struct PedersenCommitment {
    pub(crate) inner: pedersen::PedersenCommitment,
}

crate::conversion::impl_inner_conversion!(PedersenCommitment, pedersen::PedersenCommitment);

#[wasm_bindgen]
impl PedersenCommitment {
    /// Creates the identity Pedersen commitment.
    #[wasm_bindgen(js_name = "zero")]
    pub fn zero() -> Self {
        Self {
            inner: pedersen::PedersenCommitment::default(),
        }
    }

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

    /// Adds two Pedersen commitments.
    #[wasm_bindgen(js_name = "add")]
    pub fn add(&self, other: &PedersenCommitment) -> PedersenCommitment {
        PedersenCommitment {
            inner: self.inner + other.inner,
        }
    }

    /// Subtracts another Pedersen commitment from this commitment.
    #[wasm_bindgen(js_name = "subtract")]
    pub fn subtract(&self, other: &PedersenCommitment) -> PedersenCommitment {
        PedersenCommitment {
            inner: self.inner - other.inner,
        }
    }

    /// Multiplies a Pedersen commitment by a 64-bit scalar.
    #[wasm_bindgen(js_name = "multiplyByU64")]
    pub fn multiply_by_u64(&self, scalar: u64) -> PedersenCommitment {
        PedersenCommitment {
            inner: self.inner * scalar,
        }
    }

    /// Combines low and high Pedersen commitments as `lo + hi * 2^bit_length`.
    #[wasm_bindgen(js_name = "combineLoHi")]
    pub fn combine_lo_hi(
        lo: &PedersenCommitment,
        hi: &PedersenCommitment,
        bit_length: u8,
    ) -> Result<PedersenCommitment, JsValue> {
        Ok(lo.add(&hi.multiply_by_u64(lo_hi_multiplier(bit_length)?)))
    }
}

#[wasm_bindgen]
pub struct PedersenOpening {
    pub(crate) inner: pedersen::PedersenOpening,
}

crate::conversion::impl_inner_conversion!(PedersenOpening, pedersen::PedersenOpening);

#[wasm_bindgen]
impl PedersenOpening {
    /// Creates a zero Pedersen opening.
    #[wasm_bindgen(js_name = "zero")]
    pub fn zero() -> Self {
        Self {
            inner: pedersen::PedersenOpening::default(),
        }
    }

    /// Creates a new, random Pedersen opening.
    #[wasm_bindgen(constructor)]
    pub fn new_rand() -> Self {
        Self {
            inner: pedersen::PedersenOpening::new_rand(),
        }
    }

    /// Adds two Pedersen openings.
    #[wasm_bindgen(js_name = "add")]
    pub fn add(&self, other: &PedersenOpening) -> PedersenOpening {
        PedersenOpening {
            inner: &self.inner + &other.inner,
        }
    }

    /// Subtracts another Pedersen opening from this opening.
    #[wasm_bindgen(js_name = "subtract")]
    pub fn subtract(&self, other: &PedersenOpening) -> PedersenOpening {
        PedersenOpening {
            inner: &self.inner - &other.inner,
        }
    }

    /// Multiplies a Pedersen opening by a 64-bit scalar.
    #[wasm_bindgen(js_name = "multiplyByU64")]
    pub fn multiply_by_u64(&self, scalar: u64) -> PedersenOpening {
        PedersenOpening {
            inner: &self.inner * &scalar,
        }
    }

    /// Combines low and high Pedersen openings as `lo + hi * 2^bit_length`.
    #[wasm_bindgen(js_name = "combineLoHi")]
    pub fn combine_lo_hi(
        lo: &PedersenOpening,
        hi: &PedersenOpening,
        bit_length: u8,
    ) -> Result<PedersenOpening, JsValue> {
        Ok(lo.add(&hi.multiply_by_u64(lo_hi_multiplier(bit_length)?)))
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

        // Check if the commitment matches what the zk-sdk would create.
        let expected_inner = pedersen::Pedersen::with(amount, &opening.inner);
        assert_eq!(commitment.inner, expected_inner);

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

    #[wasm_bindgen_test]
    fn test_opening_arithmetic_matches_commitment_arithmetic() {
        let opening_lo = PedersenOpening::new_rand();
        let opening_hi = PedersenOpening::new_rand();
        let amount_lo = 5u64;
        let amount_hi = 7u64;
        let bit_length = 16u8;
        let multiplier = 1u64 << bit_length;

        let commitment_lo = PedersenCommitment::with_u64(amount_lo, &opening_lo);
        let commitment_hi = PedersenCommitment::with_u64(amount_hi, &opening_hi);

        let combined_opening =
            PedersenOpening::combine_lo_hi(&opening_lo, &opening_hi, bit_length).unwrap();
        let combined_commitment =
            PedersenCommitment::combine_lo_hi(&commitment_lo, &commitment_hi, bit_length).unwrap();
        let expected_commitment =
            PedersenCommitment::with_u64(amount_lo + amount_hi * multiplier, &combined_opening);

        assert_eq!(
            combined_commitment.to_bytes(),
            expected_commitment.to_bytes()
        );
    }

    #[wasm_bindgen_test]
    fn test_subtract_commitment_and_opening() {
        let base_opening = PedersenOpening::new_rand();
        let subtracted_opening = PedersenOpening::new_rand();
        let base_amount = 42u64;
        let subtracted_amount = 11u64;

        let base_commitment = PedersenCommitment::with_u64(base_amount, &base_opening);
        let subtracted_commitment =
            PedersenCommitment::with_u64(subtracted_amount, &subtracted_opening);

        let difference_opening = base_opening.subtract(&subtracted_opening);
        let difference_commitment = base_commitment.subtract(&subtracted_commitment);
        let expected_commitment =
            PedersenCommitment::with_u64(base_amount - subtracted_amount, &difference_opening);

        assert_eq!(
            difference_commitment.to_bytes(),
            expected_commitment.to_bytes()
        );
    }

    #[wasm_bindgen_test]
    fn test_zero_opening_and_commitment() {
        let zero_opening = PedersenOpening::zero();
        let random_opening = PedersenOpening::new_rand();
        let random_commitment = PedersenCommitment::with_u64(9, &random_opening);

        let zero_commitment = PedersenCommitment::zero();
        assert_eq!(
            random_opening.add(&zero_opening).inner.as_bytes(),
            random_opening.inner.as_bytes()
        );
        assert_eq!(
            random_commitment.add(&zero_commitment).to_bytes(),
            random_commitment.to_bytes()
        );
    }
}
