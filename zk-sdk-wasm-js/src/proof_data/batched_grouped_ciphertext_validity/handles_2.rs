use {
    crate::encryption::{
        elgamal::ElGamalPubkey, grouped_elgamal::GroupedElGamalCiphertext2Handles,
        pedersen::PedersenOpening,
    },
    js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{
        batched_grouped_ciphertext_validity, ZkProofData,
    },
    wasm_bindgen::prelude::*,
};

/// A batched grouped ciphertext validity proof with two decryption handles. This proof certifies
/// the validity of two grouped ElGamal ciphertexts that are encrypted under the same public keys.
#[wasm_bindgen]
pub struct BatchedGroupedCiphertext2HandlesValidityProofData {
    pub(crate) inner:
        batched_grouped_ciphertext_validity::BatchedGroupedCiphertext2HandlesValidityProofData,
}

crate::conversion::impl_inner_conversion!(
    BatchedGroupedCiphertext2HandlesValidityProofData,
    batched_grouped_ciphertext_validity::BatchedGroupedCiphertext2HandlesValidityProofData
);

#[wasm_bindgen]
impl BatchedGroupedCiphertext2HandlesValidityProofData {
    /// Creates a new batched grouped ciphertext validity proof with two handles.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        grouped_ciphertext_lo: &GroupedElGamalCiphertext2Handles,
        grouped_ciphertext_hi: &GroupedElGamalCiphertext2Handles,
        amount_lo: u64,
        amount_hi: u64,
        opening_lo: &PedersenOpening,
        opening_hi: &PedersenOpening,
    ) -> Result<BatchedGroupedCiphertext2HandlesValidityProofData, JsValue> {
        batched_grouped_ciphertext_validity::BatchedGroupedCiphertext2HandlesValidityProofData::new(
            &first_pubkey.inner,
            &second_pubkey.inner,
            &grouped_ciphertext_lo.inner,
            &grouped_ciphertext_hi.inner,
            amount_lo,
            amount_hi,
            &opening_lo.inner,
            &opening_hi.inner,
        )
        .map(|inner| Self { inner })
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the context data associated with the proof.
    #[wasm_bindgen]
    pub fn context(&self) -> BatchedGroupedCiphertext2HandlesValidityProofContext {
        self.inner.context.into()
    }

    /// Verifies the batched grouped ciphertext 2-handles validity proof.
    /// Throws an error if the proof is invalid.
    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify_proof()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes a batched grouped ciphertext validity proof with two handles from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &Uint8Array,
    ) -> Result<BatchedGroupedCiphertext2HandlesValidityProofData, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize = std::mem::size_of::<
            batched_grouped_ciphertext_validity::BatchedGroupedCiphertext2HandlesValidityProofData,
        >();
        if bytes.length() as usize != EXPECTED_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for BatchedGroupedCiphertext2HandlesValidityProof: expected {}, got {}",
                EXPECTED_LEN,
                bytes.length()
            )));
        }

        let mut data = [0u8; EXPECTED_LEN];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &batched_grouped_ciphertext_validity::BatchedGroupedCiphertext2HandlesValidityProofData| Self { inner: *pod })
            .map_err(|_| {
                JsValue::from_str("Invalid bytes for BatchedGroupedCiphertext2HandlesValidityProof")
            })
    }

    /// Serializes the batched grouped ciphertext validity proof with two handles to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

/// The context data needed to verify a batched grouped ciphertext 2-handles validity proof.
#[wasm_bindgen]
pub struct BatchedGroupedCiphertext2HandlesValidityProofContext {
    pub(crate) inner:
        batched_grouped_ciphertext_validity::BatchedGroupedCiphertext2HandlesValidityProofContext,
}

crate::conversion::impl_inner_conversion!(
    BatchedGroupedCiphertext2HandlesValidityProofContext,
    batched_grouped_ciphertext_validity::BatchedGroupedCiphertext2HandlesValidityProofContext
);

#[wasm_bindgen]
impl BatchedGroupedCiphertext2HandlesValidityProofContext {
    /// Deserializes a batched grouped ciphertext 2-handles validity proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &Uint8Array,
    ) -> Result<BatchedGroupedCiphertext2HandlesValidityProofContext, JsValue> {
        let expected_len =
            std::mem::size_of::<batched_grouped_ciphertext_validity::BatchedGroupedCiphertext2HandlesValidityProofContext>();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for BatchedGroupedCiphertext2HandlesValidityProofContext: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }
        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);
        bytemuck::try_from_bytes(&data)
            .map(|pod: &batched_grouped_ciphertext_validity::BatchedGroupedCiphertext2HandlesValidityProofContext| Self { inner: *pod })
            .map_err(|_| {
                JsValue::from_str(
                    "Invalid bytes for BatchedGroupedCiphertext2HandlesValidityProofContext",
                )
            })
    }

    /// Serializes the batched grouped ciphertext 2-handles validity proof context to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*, crate::encryption::elgamal::ElGamalKeypair,
        solana_zk_sdk::encryption::grouped_elgamal::GroupedElGamal, wasm_bindgen_test::*,
    };

    #[wasm_bindgen_test]
    fn test_batched_grouped_ciphertext_2_handles_validity_proof_creation_and_verification() {
        let first_keypair = ElGamalKeypair::new_rand();
        let second_keypair = ElGamalKeypair::new_rand();
        let amount_lo: u64 = 11;
        let amount_hi: u64 = 22;
        let opening_lo = PedersenOpening::new_rand();
        let opening_hi = PedersenOpening::new_rand();

        let grouped_ciphertext_lo = GroupedElGamalCiphertext2Handles {
            inner: GroupedElGamal::encrypt_with(
                [
                    &first_keypair.pubkey().inner,
                    &second_keypair.pubkey().inner,
                ],
                amount_lo,
                &opening_lo.inner,
            ),
        };

        let grouped_ciphertext_hi = GroupedElGamalCiphertext2Handles {
            inner: GroupedElGamal::encrypt_with(
                [
                    &first_keypair.pubkey().inner,
                    &second_keypair.pubkey().inner,
                ],
                amount_hi,
                &opening_hi.inner,
            ),
        };

        let proof = BatchedGroupedCiphertext2HandlesValidityProofData::new(
            &first_keypair.pubkey(),
            &second_keypair.pubkey(),
            &grouped_ciphertext_lo,
            &grouped_ciphertext_hi,
            amount_lo,
            amount_hi,
            &opening_lo,
            &opening_hi,
        )
        .unwrap();

        assert!(proof.verify().is_ok());
    }

    #[wasm_bindgen_test]
    fn test_batched_grouped_ciphertext_2_handles_validity_proof_bytes_roundtrip() {
        let first_keypair = ElGamalKeypair::new_rand();
        let second_keypair = ElGamalKeypair::new_rand();
        let amount_lo: u64 = 11;
        let amount_hi: u64 = 22;
        let opening_lo = PedersenOpening::new_rand();
        let opening_hi = PedersenOpening::new_rand();

        let grouped_ciphertext_lo = GroupedElGamalCiphertext2Handles {
            inner: GroupedElGamal::encrypt_with(
                [
                    &first_keypair.pubkey().inner,
                    &second_keypair.pubkey().inner,
                ],
                amount_lo,
                &opening_lo.inner,
            ),
        };

        let grouped_ciphertext_hi = GroupedElGamalCiphertext2Handles {
            inner: GroupedElGamal::encrypt_with(
                [
                    &first_keypair.pubkey().inner,
                    &second_keypair.pubkey().inner,
                ],
                amount_hi,
                &opening_hi.inner,
            ),
        };

        let proof = BatchedGroupedCiphertext2HandlesValidityProofData::new(
            &first_keypair.pubkey(),
            &second_keypair.pubkey(),
            &grouped_ciphertext_lo,
            &grouped_ciphertext_hi,
            amount_lo,
            amount_hi,
            &opening_lo,
            &opening_hi,
        )
        .unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof = BatchedGroupedCiphertext2HandlesValidityProofData::from_bytes(
            &Uint8Array::from(bytes.as_slice()),
        )
        .unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        let context = proof.context();
        let context_bytes = context.to_bytes();
        let recovered_context = BatchedGroupedCiphertext2HandlesValidityProofContext::from_bytes(
            &Uint8Array::from(context_bytes.as_slice()),
        )
        .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }
}
