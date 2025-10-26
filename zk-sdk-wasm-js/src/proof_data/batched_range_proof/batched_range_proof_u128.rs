use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        proof_data::batched_range_proof::BatchedRangeProofContext,
    },
    js_sys::{BigUint64Array, Uint8Array},
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{self, ZkProofData},
    wasm_bindgen::prelude::*,
};

/// A 128-bit batched range proof.
///
/// This proof certifies that a batch of Pedersen commitments encrypt values
/// that are within specified bit ranges, summing up to 128 bits in total.
#[wasm_bindgen]
pub struct BatchedRangeProofU128Data {
    pub(crate) inner: proof_data::BatchedRangeProofU128Data,
}

crate::conversion::impl_inner_conversion!(
    BatchedRangeProofU128Data,
    proof_data::BatchedRangeProofU128Data
);

#[wasm_bindgen]
impl BatchedRangeProofU128Data {
    /// Creates a new 128-bit batched range proof.
    ///
    /// The function takes arrays of Pedersen commitments, amounts (as BigUint64Array),
    /// bit lengths (as Uint8Array), and Pedersen openings. The sum of bit lengths must be 128,
    /// and each bit length must be a power of two.
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
    ) -> Result<BatchedRangeProofU128Data, JsValue> {
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

        proof_data::BatchedRangeProofU128Data::new(
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

    /// Verifies the 128-bit batched range proof.
    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify_proof()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes a 128-bit batched range proof from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<BatchedRangeProofU128Data, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize = std::mem::size_of::<proof_data::BatchedRangeProofU128Data>();
        if bytes.length() as usize != EXPECTED_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for BatchedRangeProofU128: expected {}, got {}",
                EXPECTED_LEN,
                bytes.length()
            )));
        }

        let mut data = [0u8; EXPECTED_LEN];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &proof_data::BatchedRangeProofU128Data| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for BatchedRangeProofU128"))
    }

    /// Serializes the 128-bit batched range proof to a byte array.
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
    fn test_batched_range_proof_u128_creation_and_verification() {
        // Case 1: Success (e.g., 2 * 64 bits = 128 bits). All powers of two.
        let amounts_vec = vec![u64::MAX, u64::MAX];
        let openings_vec: Vec<_> = (0..2).map(|_| PedersenOpening::new_rand()).collect();
        let commitments_vec: Vec<_> = amounts_vec
            .iter()
            .zip(openings_vec.iter())
            .map(|(amount, opening)| PedersenCommitment::with_u64(*amount, opening))
            .collect();

        let commitments = commitments_vec.into_boxed_slice();
        let amounts = BigUint64Array::from(amounts_vec.as_slice());
        let bit_lengths = Uint8Array::from(vec![64_u8, 64_u8].as_slice());
        let openings = openings_vec.into_boxed_slice();

        // Inputs are moved here
        let proof =
            BatchedRangeProofU128Data::new(commitments, amounts, bit_lengths, openings).unwrap();
        assert!(proof.verify().is_ok());

        // Case 2: Failure (Amount exceeds bit length)
        // Setup: 32 bits + 32 bits + 64 bits = 128 bits. All powers of two.
        let amount_1_invalid = 1_u64 << 32; // Requires 33 bits
        let amount_2_valid = 1_u64;
        let amount_3_valid = 1_u64;

        // Regenerate data as inputs were moved
        let opening_1_invalid = PedersenOpening::new_rand();
        let opening_2_valid = PedersenOpening::new_rand();
        let opening_3_valid = PedersenOpening::new_rand();

        let commitment_1_invalid =
            PedersenCommitment::with_u64(amount_1_invalid, &opening_1_invalid);
        let commitment_2_valid = PedersenCommitment::with_u64(amount_2_valid, &opening_2_valid);
        let commitment_3_valid = PedersenCommitment::with_u64(amount_3_valid, &opening_3_valid);

        let commitments_invalid =
            vec![commitment_1_invalid, commitment_2_valid, commitment_3_valid].into_boxed_slice();
        let amounts_invalid =
            BigUint64Array::from(vec![amount_1_invalid, amount_2_valid, amount_3_valid].as_slice());
        // Ensure all are powers of two and sum to 128.
        let bit_lengths_for_invalid = Uint8Array::from(vec![32_u8, 32_u8, 64_u8].as_slice());
        let openings_invalid =
            vec![opening_1_invalid, opening_2_valid, opening_3_valid].into_boxed_slice();

        // Proof generation succeeds because the structure (bit lengths) is valid.
        let proof_invalid = BatchedRangeProofU128Data::new(
            commitments_invalid,
            amounts_invalid,
            bit_lengths_for_invalid,
            openings_invalid,
        )
        .unwrap();

        // Verification must fail because amount_1_invalid does not fit in 32 bits.
        assert!(proof_invalid.verify().is_err());

        // Case 3: Failure (Total bit length != 128)
        // Regenerate data
        let amount_valid = 10_u64;
        let opening_valid = PedersenOpening::new_rand();
        let commitment_valid = PedersenCommitment::with_u64(amount_valid, &opening_valid);

        let result = BatchedRangeProofU128Data::new(
            vec![commitment_valid].into_boxed_slice(),
            BigUint64Array::from(vec![amount_valid].as_slice()),
            // Sum is 64, not 128.
            Uint8Array::from(vec![64_u8].as_slice()),
            vec![opening_valid].into_boxed_slice(),
        );
        // Proof generation should fail.
        assert!(result.is_err());

        // Case 4: Failure (Bit length not a power of two)
        let amount_1 = 1_u64;
        let amount_2 = 1_u64;
        let opening_1 = PedersenOpening::new_rand();
        let opening_2 = PedersenOpening::new_rand();
        let commitment_1 = PedersenCommitment::with_u64(amount_1, &opening_1);
        let commitment_2 = PedersenCommitment::with_u64(amount_2, &opening_2);

        let result_pow2 = BatchedRangeProofU128Data::new(
            vec![commitment_1, commitment_2].into_boxed_slice(),
            BigUint64Array::from(vec![amount_1, amount_2].as_slice()),
            // 96 is not a power of two.
            Uint8Array::from(vec![32_u8, 96_u8].as_slice()),
            vec![opening_1, opening_2].into_boxed_slice(),
        );
        // Proof generation should fail because the structure is invalid.
        assert!(result_pow2.is_err());
    }

    #[wasm_bindgen_test]
    fn test_batched_range_proof_u128_bytes_roundtrip() {
        // Two commitments, 64 bits each
        let amounts_vec = vec![1_u64, 2_u64];
        let openings_vec: Vec<_> = (0..2).map(|_| PedersenOpening::new_rand()).collect();
        let commitments_vec: Vec<_> = amounts_vec
            .iter()
            .zip(openings_vec.iter())
            .map(|(amount, opening)| PedersenCommitment::with_u64(*amount, opening))
            .collect();

        let proof = BatchedRangeProofU128Data::new(
            commitments_vec.into_boxed_slice(),
            BigUint64Array::from(amounts_vec.as_slice()),
            Uint8Array::from(vec![64_u8, 64_u8].as_slice()),
            openings_vec.into_boxed_slice(),
        )
        .unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof =
            BatchedRangeProofU128Data::from_bytes(&Uint8Array::from(bytes.as_slice())).unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());
    }
}
