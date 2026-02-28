use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        proof_data::batched_range_proof::BatchedRangeProofContext,
    },
    js_sys::{BigUint64Array, Uint8Array},
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{
        self, batched_range_proof::batched_range_proof_u256, VerifyZkProof,
    },
    wasm_bindgen::prelude::*,
};

/// A 256-bit batched range proof.
///
/// This proof certifies that a batch of Pedersen commitments encrypt values
/// that are within specified bit ranges, summing up to 256 bits in total.
/// Each individual bit length must not exceed 128.
#[wasm_bindgen]
pub struct BatchedRangeProofU256Data {
    pub(crate) inner: proof_data::BatchedRangeProofU256Data,
}

crate::conversion::impl_inner_conversion!(
    BatchedRangeProofU256Data,
    proof_data::BatchedRangeProofU256Data
);

#[wasm_bindgen]
impl BatchedRangeProofU256Data {
    /// Creates a new 256-bit batched range proof.
    ///
    /// The function takes arrays of Pedersen commitments, amounts (as BigUint64Array),
    /// bit lengths (as Uint8Array), and Pedersen openings. The sum of bit lengths must be 256,
    /// and each bit length must be a power of two less than or equal to 128.
    ///
    /// # Arguments
    ///
    /// * `commitments` - An array of `PedersenCommitment`.
    /// * `amounts` - An array of 64-bit amounts (as `BigUint64Array`).
    /// * `bit_lengths` - An array of bit lengths (as `Uint8Array`).
    /// * `openings` - An array of `PedersenOpening`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        commitments: Box<[PedersenCommitment]>,
        amounts: BigUint64Array,
        bit_lengths: Uint8Array,
        openings: Box<[PedersenOpening]>,
    ) -> Result<BatchedRangeProofU256Data, JsValue> {
        // Check array lengths for early exit and clearer error messages
        if commitments.len() != amounts.length() as usize
            || commitments.len() != bit_lengths.length() as usize
            || commitments.len() != openings.len()
        {
            return Err(JsValue::from_str("Mismatched lengths of input arrays"));
        }

        let commitments_inner: Vec<_> = commitments.iter().map(|c| &c.inner).collect();
        let amounts_vec = amounts.to_vec();
        let bit_lengths_vec: Vec<usize> = bit_lengths
            .to_vec()
            .into_iter()
            .map(|x| x as usize)
            .collect();
        let openings_inner: Vec<_> = openings.iter().map(|o| &o.inner).collect();

        batched_range_proof_u256::build_batched_range_proof_u256_data(
            commitments_inner,
            amounts_vec,
            bit_lengths_vec,
            openings_inner,
        )
        .map(|inner| Self { inner })
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the context data associated with the proof.
    #[wasm_bindgen]
    pub fn context(&self) -> BatchedRangeProofContext {
        self.inner.context.into()
    }

    /// Verifies the 256-bit batched range proof.
    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify_proof()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes a 256-bit batched range proof from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<BatchedRangeProofU256Data, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize = std::mem::size_of::<proof_data::BatchedRangeProofU256Data>();
        if bytes.length() as usize != EXPECTED_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for BatchedRangeProofU256: expected {}, got {}",
                EXPECTED_LEN,
                bytes.length()
            )));
        }

        let mut data = vec![0u8; EXPECTED_LEN];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &proof_data::BatchedRangeProofU256Data| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for BatchedRangeProofU256"))
    }

    /// Serializes the 256-bit batched range proof to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::encryption::pedersen::{PedersenCommitment, PedersenOpening},
        wasm_bindgen_test::*,
    };

    #[wasm_bindgen_test]
    fn test_batched_range_proof_u256_creation_and_verification() {
        // Case 1: Success (e.g., 4 * 64 bits = 256 bits). All powers of two.
        let amounts_vec = vec![1_u64, 2_u64, 3_u64, 4_u64];
        let openings_vec: Vec<_> = (0..4).map(|_| PedersenOpening::new_rand()).collect();
        let commitments_vec: Vec<_> = amounts_vec
            .iter()
            .zip(openings_vec.iter())
            .map(|(amount, opening)| PedersenCommitment::with_u64(*amount, opening))
            .collect();

        let commitments = commitments_vec.into_boxed_slice();
        let amounts = BigUint64Array::from(amounts_vec.as_slice());
        let bit_lengths = Uint8Array::from(vec![64_u8, 64_u8, 64_u8, 64_u8].as_slice());
        let openings = openings_vec.into_boxed_slice();

        // Inputs are moved into new()
        let proof =
            BatchedRangeProofU256Data::new(commitments, amounts, bit_lengths.clone(), openings)
                .unwrap();
        assert!(proof.verify().is_ok());

        // Case 2: Failure (Amount exceeds bit length)
        // Setup: 32, 64, 64, 64, 32 bits = 256 bits. All powers of two.
        let amount_1_invalid = 1_u64 << 32; // Requires 33 bits

        // Must regenerate inputs as they were moved in Case 1.
        let amounts_invalid_vec = vec![amount_1_invalid, 2_u64, 3_u64, 4_u64, 5_u64];
        let openings_invalid_vec: Vec<_> = (0..5).map(|_| PedersenOpening::new_rand()).collect();
        let commitments_invalid_vec: Vec<_> = amounts_invalid_vec
            .iter()
            .zip(openings_invalid_vec.iter())
            .map(|(amount, opening)| PedersenCommitment::with_u64(*amount, opening))
            .collect();

        // Ensure all are powers of two and sum is 256.
        let bit_lengths_for_exceed =
            Uint8Array::from(vec![32_u8, 64_u8, 64_u8, 64_u8, 32_u8].as_slice());

        // Proof generation succeeds because the structure (bit lengths) is valid.
        let proof_invalid = BatchedRangeProofU256Data::new(
            commitments_invalid_vec.into_boxed_slice(),
            BigUint64Array::from(amounts_invalid_vec.as_slice()),
            bit_lengths_for_exceed,
            openings_invalid_vec.into_boxed_slice(),
        )
        .unwrap();

        // Verification must fail because the first amount doesn't fit in 32 bits.
        assert!(proof_invalid.verify().is_err());

        // Case 3: Failure (Individual bit length > 128)
        // Setup: 32 bits + 224 bits = 256 bits. 224 > 128.

        // Regenerate inputs.
        let amount_1_valid = 1_u64;
        let amount_2_valid = 1_u64;
        let opening_1_valid = PedersenOpening::new_rand();
        let opening_2_valid = PedersenOpening::new_rand();
        let commitment_1_valid = PedersenCommitment::with_u64(amount_1_valid, &opening_1_valid);
        let commitment_2_valid = PedersenCommitment::with_u64(amount_2_valid, &opening_2_valid);

        let commitments_invalid_len =
            vec![commitment_1_valid, commitment_2_valid].into_boxed_slice();
        let amounts_invalid_len =
            BigUint64Array::from(vec![amount_1_valid, amount_2_valid].as_slice());
        // Note: 224 is also not a power of two, but the SDK checks the > 128 constraint first for U256.
        let bit_lengths_for_invalid = Uint8Array::from(vec![32_u8, 224_u8].as_slice());
        let openings_invalid_len = vec![opening_1_valid, opening_2_valid].into_boxed_slice();

        // Proof generation itself should fail due to bit length > 128
        let proof_gen_result = BatchedRangeProofU256Data::new(
            commitments_invalid_len,
            amounts_invalid_len,
            bit_lengths_for_invalid,
            openings_invalid_len,
        );
        assert!(proof_gen_result.is_err());

        // Case 4: Failure (Total bit length != 256)
        // Regenerate inputs.
        let amounts_vec_case4 = vec![1_u64, 2_u64];
        let openings_vec_case4: Vec<_> = (0..2).map(|_| PedersenOpening::new_rand()).collect();
        let commitments_vec_case4: Vec<_> = amounts_vec_case4
            .iter()
            .zip(openings_vec_case4.iter())
            .map(|(amount, opening)| PedersenCommitment::with_u64(*amount, opening))
            .collect();

        // Sum is 192, not 256.
        let bit_lengths_wrong_sum = Uint8Array::from(vec![128_u8, 64_u8].as_slice());

        let result = BatchedRangeProofU256Data::new(
            commitments_vec_case4.into_boxed_slice(),
            BigUint64Array::from(amounts_vec_case4.as_slice()),
            bit_lengths_wrong_sum,
            openings_vec_case4.into_boxed_slice(),
        );
        assert!(result.is_err());

        // Case 5: Failure (Bit length not a power of two)
        let amounts_vec_case5 = vec![1_u64, 2_u64];
        let openings_vec_case5: Vec<_> = (0..2).map(|_| PedersenOpening::new_rand()).collect();
        let commitments_vec_case5: Vec<_> = amounts_vec_case5
            .iter()
            .zip(openings_vec_case5.iter())
            .map(|(amount, opening)| PedersenCommitment::with_u64(*amount, opening))
            .collect();

        // 96 and 160 are not powers of two. Sum is 256.
        let bit_lengths_not_pow2 = Uint8Array::from(vec![160_u8, 96_u8].as_slice());

        let result_pow2 = BatchedRangeProofU256Data::new(
            commitments_vec_case5.into_boxed_slice(),
            BigUint64Array::from(amounts_vec_case5.as_slice()),
            bit_lengths_not_pow2,
            openings_vec_case5.into_boxed_slice(),
        );
        // Proof generation should fail because the structure is invalid.
        assert!(result_pow2.is_err());
    }

    #[wasm_bindgen_test]
    fn test_batched_range_proof_u256_bytes_roundtrip() {
        let amounts_vec = vec![10_u64, 20_u64, 30_u64, 40_u64];
        let bit_lengths_vec = vec![64_u8, 64_u8, 64_u8, 64_u8];
        let openings_vec: Vec<_> = (0..4).map(|_| PedersenOpening::new_rand()).collect();
        let commitments_vec: Vec<_> = amounts_vec
            .iter()
            .zip(openings_vec.iter())
            .map(|(amount, opening)| PedersenCommitment::with_u64(*amount, opening))
            .collect();

        let proof = BatchedRangeProofU256Data::new(
            commitments_vec.into_boxed_slice(),
            BigUint64Array::from(amounts_vec.as_slice()),
            Uint8Array::from(bit_lengths_vec.as_slice()),
            openings_vec.into_boxed_slice(),
        )
        .unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof =
            BatchedRangeProofU256Data::from_bytes(&Uint8Array::from(bytes.as_slice())).unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());
    }
}
