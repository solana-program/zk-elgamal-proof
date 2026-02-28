use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        proof_data::batched_range_proof::BatchedRangeProofContext,
    },
    js_sys::{BigUint64Array, Uint8Array},
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{
        self, batched_range_proof::batched_range_proof_u64, VerifyZkProof,
    },
    wasm_bindgen::prelude::*,
};

/// A 64-bit batched range proof.
///
/// This proof certifies that a batch of Pedersen commitments encrypt values
/// that are within specified bit ranges, summing up to 64 bits in total.
#[wasm_bindgen]
pub struct BatchedRangeProofU64Data {
    pub(crate) inner: proof_data::BatchedRangeProofU64Data,
}

crate::conversion::impl_inner_conversion!(
    BatchedRangeProofU64Data,
    proof_data::BatchedRangeProofU64Data
);

#[wasm_bindgen]
impl BatchedRangeProofU64Data {
    /// Creates a new 64-bit batched range proof.
    ///
    /// The function takes arrays of Pedersen commitments, amounts (as BigUint64Array),
    /// bit lengths (as Uint8Array), and Pedersen openings. The sum of bit lengths must be 64.
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
    ) -> Result<BatchedRangeProofU64Data, JsValue> {
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

        batched_range_proof_u64::build_batched_range_proof_u64_data(
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

    /// Verifies the 64-bit batched range proof.
    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify_proof()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes a 64-bit batched range proof from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<BatchedRangeProofU64Data, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize = std::mem::size_of::<proof_data::BatchedRangeProofU64Data>();
        if bytes.length() as usize != EXPECTED_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for BatchedRangeProofU64: expected {}, got {}",
                EXPECTED_LEN,
                bytes.length()
            )));
        }

        let mut data = [0u8; EXPECTED_LEN];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &proof_data::BatchedRangeProofU64Data| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for BatchedRangeProofU64"))
    }

    /// Serializes the 64-bit batched range proof to a byte array.
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
    fn test_batched_range_proof_u64_creation_and_verification() {
        // Case 1: Success (e.g., 8 bits + 56 bits = 64 bits)
        let amount_1 = 255_u64; // Max 8-bit number
        let amount_2 = (1_u64 << 56) - 1; // Max 56-bit number

        let opening_1 = PedersenOpening::new_rand();
        let opening_2 = PedersenOpening::new_rand();

        let commitment_1 = PedersenCommitment::with_u64(amount_1, &opening_1);
        let commitment_2 = PedersenCommitment::with_u64(amount_2, &opening_2);

        // Prepare inputs using into_boxed_slice() for Box<[T]>
        let commitments = vec![commitment_1, commitment_2].into_boxed_slice();
        // Note: BigUint64Array::from() works in most wasm-bindgen-test setups.
        let amounts = BigUint64Array::from(vec![amount_1, amount_2].as_slice());
        let bit_lengths = Uint8Array::from(vec![8_u8, 56_u8].as_slice());
        let openings = vec![opening_1, opening_2].into_boxed_slice();

        let proof =
            BatchedRangeProofU64Data::new(commitments, amounts, bit_lengths.clone(), openings)
                .unwrap();

        assert!(proof.verify().is_ok());

        // Case 2: Failure (Amount exceeds bit length)
        let amount_1_invalid = 256_u64; // Requires 9 bits
        let amount_2_valid = 1_u64;

        let opening_1_invalid = PedersenOpening::new_rand();
        let opening_2_valid = PedersenOpening::new_rand();

        let commitment_1_invalid =
            PedersenCommitment::with_u64(amount_1_invalid, &opening_1_invalid);
        let commitment_2_valid = PedersenCommitment::with_u64(amount_2_valid, &opening_2_valid);

        let commitments_invalid = vec![commitment_1_invalid, commitment_2_valid].into_boxed_slice();
        let amounts_invalid =
            BigUint64Array::from(vec![amount_1_invalid, amount_2_valid].as_slice());
        // bit_lengths is still [8, 56]
        let openings_invalid = vec![opening_1_invalid, opening_2_valid].into_boxed_slice();

        // Proof generation succeeds (as the amounts are provided), but verification must fail.
        let proof_invalid = BatchedRangeProofU64Data::new(
            commitments_invalid,
            amounts_invalid,
            bit_lengths,
            openings_invalid,
        )
        .unwrap();

        assert!(proof_invalid.verify().is_err());

        // Case 3: Failure (Total bit length != 64)
        let amount_valid = 10_u64;
        let opening_valid = PedersenOpening::new_rand();
        let commitment_valid = PedersenCommitment::with_u64(amount_valid, &opening_valid);

        let commitments_valid = vec![commitment_valid].into_boxed_slice();
        let amounts_valid = BigUint64Array::from(vec![amount_valid].as_slice());
        let bit_lengths_wrong_sum = Uint8Array::from(vec![63_u8].as_slice()); // Sum is 63
        let openings_valid = vec![opening_valid].into_boxed_slice();

        let result = BatchedRangeProofU64Data::new(
            commitments_valid,
            amounts_valid,
            bit_lengths_wrong_sum,
            openings_valid,
        );
        // Proof generation should fail because the sum of bit lengths is not 64.
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_batched_range_proof_u64_bytes_roundtrip() {
        // Single commitment, 64 bits
        let amount = u64::MAX;
        let opening = PedersenOpening::new_rand();
        let commitment = PedersenCommitment::with_u64(amount, &opening);

        let commitments = vec![commitment].into_boxed_slice();
        let amounts = BigUint64Array::from(vec![amount].as_slice());
        let bit_lengths = Uint8Array::from(vec![64_u8].as_slice());
        let openings = vec![opening].into_boxed_slice();

        let proof =
            BatchedRangeProofU64Data::new(commitments, amounts, bit_lengths, openings).unwrap();

        // Test proof roundtrip
        let bytes = proof.to_bytes();
        let recovered_proof =
            BatchedRangeProofU64Data::from_bytes(&Uint8Array::from(bytes.as_slice())).unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        // Test context roundtrip
        let context = proof.context();
        let context_bytes = context.to_bytes();
        // Use the context wrapper from the parent module for deserialization
        let recovered_context =
            BatchedRangeProofContext::from_bytes(&Uint8Array::from(context_bytes.as_slice()))
                .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_mismatched_input_lengths() {
        // Test mismatch between commitments and openings
        let amount = 1_u64;
        let opening = PedersenOpening::new_rand();
        let commitment = PedersenCommitment::with_u64(amount, &opening);

        let commitments = vec![commitment].into_boxed_slice();
        let amounts = BigUint64Array::from(vec![1_u64].as_slice());
        let bit_lengths = Uint8Array::from(vec![64_u8].as_slice());
        let openings_mismatch = vec![].into_boxed_slice(); // Mismatch: expected 1, got 0

        let result =
            BatchedRangeProofU64Data::new(commitments, amounts, bit_lengths, openings_mismatch);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().as_string().unwrap(),
            "Mismatched lengths of input arrays"
        );
    }
}
