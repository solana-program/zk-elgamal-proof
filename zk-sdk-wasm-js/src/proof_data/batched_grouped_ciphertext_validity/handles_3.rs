use {
    crate::encryption::{
        elgamal::ElGamalPubkey, grouped_elgamal::GroupedElGamalCiphertext3Handles,
        pedersen::PedersenOpening,
    },
    js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{
        BatchedGroupedCiphertext3HandlesValidityProofDataExt, ZkProofData,
    },
    solana_zk_sdk_pod::proof_data::batched_grouped_ciphertext_validity,
    wasm_bindgen::prelude::*,
};

/// A batched grouped ciphertext validity proof with three decryption handles. This proof certifies
/// the validity of two grouped ElGamal ciphertexts that are encrypted under the same public keys.
#[wasm_bindgen]
pub struct BatchedGroupedCiphertext3HandlesValidityProofData {
    pub(crate) inner:
        batched_grouped_ciphertext_validity::BatchedGroupedCiphertext3HandlesValidityProofData,
}

crate::conversion::impl_inner_conversion!(
    BatchedGroupedCiphertext3HandlesValidityProofData,
    batched_grouped_ciphertext_validity::BatchedGroupedCiphertext3HandlesValidityProofData
);

#[wasm_bindgen]
impl BatchedGroupedCiphertext3HandlesValidityProofData {
    /// Creates a new batched grouped ciphertext validity proof with three handles.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        third_pubkey: &ElGamalPubkey,
        grouped_ciphertext_lo: &GroupedElGamalCiphertext3Handles,
        grouped_ciphertext_hi: &GroupedElGamalCiphertext3Handles,
        amount_lo: u64,
        amount_hi: u64,
        opening_lo: &PedersenOpening,
        opening_hi: &PedersenOpening,
    ) -> Result<BatchedGroupedCiphertext3HandlesValidityProofData, JsValue> {
        batched_grouped_ciphertext_validity::BatchedGroupedCiphertext3HandlesValidityProofData::new(
            &first_pubkey.inner,
            &second_pubkey.inner,
            &third_pubkey.inner,
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
    pub fn context(&self) -> BatchedGroupedCiphertext3HandlesValidityProofContext {
        self.inner.context.into()
    }

    /// Verifies the batched grouped ciphertext 3-handles validity proof.
    /// Throws an error if the proof is invalid.
    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify_proof()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes a batched grouped ciphertext validity proof with three handles from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &Uint8Array,
    ) -> Result<BatchedGroupedCiphertext3HandlesValidityProofData, JsValue> {
        let expected_len = std::mem::size_of::<
            batched_grouped_ciphertext_validity::BatchedGroupedCiphertext3HandlesValidityProofData,
        >();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for BatchedGroupedCiphertext3HandlesValidityProof: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }

        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &batched_grouped_ciphertext_validity::BatchedGroupedCiphertext3HandlesValidityProofData| Self { inner: *pod })
            .map_err(|_| {
                JsValue::from_str("Invalid bytes for BatchedGroupedCiphertext3HandlesValidityProof")
            })
    }

    /// Serializes the batched grouped ciphertext validity proof with three handles to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

/// The context data needed to verify a batched grouped ciphertext 3-handles validity proof.
#[wasm_bindgen]
pub struct BatchedGroupedCiphertext3HandlesValidityProofContext {
    pub(crate) inner:
        batched_grouped_ciphertext_validity::BatchedGroupedCiphertext3HandlesValidityProofContext,
}

crate::conversion::impl_inner_conversion!(
    BatchedGroupedCiphertext3HandlesValidityProofContext,
    batched_grouped_ciphertext_validity::BatchedGroupedCiphertext3HandlesValidityProofContext
);

#[wasm_bindgen]
impl BatchedGroupedCiphertext3HandlesValidityProofContext {
    /// Deserializes a batched grouped ciphertext 3-handles validity proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &Uint8Array,
    ) -> Result<BatchedGroupedCiphertext3HandlesValidityProofContext, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize =
            std::mem::size_of::<batched_grouped_ciphertext_validity::BatchedGroupedCiphertext3HandlesValidityProofContext>();
        if bytes.length() as usize != EXPECTED_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for BatchedGroupedCiphertext3HandlesValidityProofContext: expected {}, got {}",
                EXPECTED_LEN,
                bytes.length()
            )));
        }
        let mut data = [0u8; EXPECTED_LEN];
        bytes.copy_to(&mut data);
        bytemuck::try_from_bytes(&data)
            .map(|pod: &batched_grouped_ciphertext_validity::BatchedGroupedCiphertext3HandlesValidityProofContext| Self { inner: *pod })
            .map_err(|_| {
                JsValue::from_str(
                    "Invalid bytes for BatchedGroupedCiphertext3HandlesValidityProofContext",
                )
            })
    }

    /// Serializes the batched grouped ciphertext 3-handles validity proof context to a byte array.
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
    fn test_batched_grouped_ciphertext_3_handles_validity_proof_creation_and_verification() {
        let first_keypair = ElGamalKeypair::new_rand();
        let second_keypair = ElGamalKeypair::new_rand();
        let third_keypair = ElGamalKeypair::new_rand();
        let amount_lo: u64 = 11;
        let amount_hi: u64 = 22;
        let opening_lo = PedersenOpening::new_rand();
        let opening_hi = PedersenOpening::new_rand();

        let grouped_ciphertext_lo = GroupedElGamalCiphertext3Handles {
            inner: GroupedElGamal::encrypt_with(
                [
                    &first_keypair.pubkey().inner,
                    &second_keypair.pubkey().inner,
                    &third_keypair.pubkey().inner,
                ],
                amount_lo,
                &opening_lo.inner,
            ),
        };

        let grouped_ciphertext_hi = GroupedElGamalCiphertext3Handles {
            inner: GroupedElGamal::encrypt_with(
                [
                    &first_keypair.pubkey().inner,
                    &second_keypair.pubkey().inner,
                    &third_keypair.pubkey().inner,
                ],
                amount_hi,
                &opening_hi.inner,
            ),
        };

        let proof = BatchedGroupedCiphertext3HandlesValidityProofData::new(
            &first_keypair.pubkey(),
            &second_keypair.pubkey(),
            &third_keypair.pubkey(),
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
    fn test_batched_grouped_ciphertext_3_handles_validity_proof_bytes_roundtrip() {
        let first_keypair = ElGamalKeypair::new_rand();
        let second_keypair = ElGamalKeypair::new_rand();
        let third_keypair = ElGamalKeypair::new_rand();
        let amount_lo: u64 = 11;
        let amount_hi: u64 = 22;
        let opening_lo = PedersenOpening::new_rand();
        let opening_hi = PedersenOpening::new_rand();

        let grouped_ciphertext_lo = GroupedElGamalCiphertext3Handles {
            inner: GroupedElGamal::encrypt_with(
                [
                    &first_keypair.pubkey().inner,
                    &second_keypair.pubkey().inner,
                    &third_keypair.pubkey().inner,
                ],
                amount_lo,
                &opening_lo.inner,
            ),
        };

        let grouped_ciphertext_hi = GroupedElGamalCiphertext3Handles {
            inner: GroupedElGamal::encrypt_with(
                [
                    &first_keypair.pubkey().inner,
                    &second_keypair.pubkey().inner,
                    &third_keypair.pubkey().inner,
                ],
                amount_hi,
                &opening_hi.inner,
            ),
        };

        let proof = BatchedGroupedCiphertext3HandlesValidityProofData::new(
            &first_keypair.pubkey(),
            &second_keypair.pubkey(),
            &third_keypair.pubkey(),
            &grouped_ciphertext_lo,
            &grouped_ciphertext_hi,
            amount_lo,
            amount_hi,
            &opening_lo,
            &opening_hi,
        )
        .unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof = BatchedGroupedCiphertext3HandlesValidityProofData::from_bytes(
            &Uint8Array::from(bytes.as_slice()),
        )
        .unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        let context = proof.context();
        let context_bytes = context.to_bytes();
        let recovered_context = BatchedGroupedCiphertext3HandlesValidityProofContext::from_bytes(
            &Uint8Array::from(context_bytes.as_slice()),
        )
        .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }
}
