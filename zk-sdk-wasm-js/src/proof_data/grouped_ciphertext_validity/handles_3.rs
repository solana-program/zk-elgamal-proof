use {
    crate::encryption::{
        elgamal::ElGamalPubkey, grouped_elgamal::GroupedElGamalCiphertext3Handles,
        pedersen::PedersenOpening,
    },
    js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{
        grouped_ciphertext_validity, ZkProofData,
    },
    wasm_bindgen::prelude::*,
};

/// A grouped ciphertext validity proof with three decryption handles. This proof certifies
/// that a given grouped ElGamal ciphertext with three handles is well-formed.
#[wasm_bindgen]
pub struct GroupedCiphertext3HandlesValidityProofData {
    pub(crate) inner: grouped_ciphertext_validity::GroupedCiphertext3HandlesValidityProofData,
}

crate::conversion::impl_inner_conversion!(
    GroupedCiphertext3HandlesValidityProofData,
    grouped_ciphertext_validity::GroupedCiphertext3HandlesValidityProofData
);

#[wasm_bindgen]
impl GroupedCiphertext3HandlesValidityProofData {
    /// Creates a new grouped ciphertext validity proof with three handles.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        third_pubkey: &ElGamalPubkey,
        grouped_ciphertext: &GroupedElGamalCiphertext3Handles,
        amount: u64,
        opening: &PedersenOpening,
    ) -> Result<GroupedCiphertext3HandlesValidityProofData, JsValue> {
        grouped_ciphertext_validity::GroupedCiphertext3HandlesValidityProofData::new(
            &first_pubkey.inner,
            &second_pubkey.inner,
            &third_pubkey.inner,
            &grouped_ciphertext.inner,
            amount,
            &opening.inner,
        )
        .map(|inner| Self { inner })
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the context data associated with the proof.
    #[wasm_bindgen]
    pub fn context(&self) -> GroupedCiphertext3HandlesValidityProofContext {
        self.inner.context.into()
    }

    /// Verifies the grouped ciphertext 3-handles validity proof.
    /// Throws an error if the proof is invalid.
    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify_proof()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes a grouped ciphertext validity proof with three handles from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &Uint8Array,
    ) -> Result<GroupedCiphertext3HandlesValidityProofData, JsValue> {
        let expected_len = std::mem::size_of::<
            grouped_ciphertext_validity::GroupedCiphertext3HandlesValidityProofData,
        >();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for GroupedCiphertext3HandlesValidityProof: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }

        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(
                |pod: &grouped_ciphertext_validity::GroupedCiphertext3HandlesValidityProofData| {
                    Self { inner: *pod }
                },
            )
            .map_err(|_| {
                JsValue::from_str("Invalid bytes for GroupedCiphertext3HandlesValidityProof")
            })
    }

    /// Serializes the grouped ciphertext validity proof with three handles to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

/// The context data needed to verify a grouped ciphertext 3-handles validity proof.
#[wasm_bindgen]
pub struct GroupedCiphertext3HandlesValidityProofContext {
    pub(crate) inner: grouped_ciphertext_validity::GroupedCiphertext3HandlesValidityProofContext,
}

crate::conversion::impl_inner_conversion!(
    GroupedCiphertext3HandlesValidityProofContext,
    grouped_ciphertext_validity::GroupedCiphertext3HandlesValidityProofContext
);

#[wasm_bindgen]
impl GroupedCiphertext3HandlesValidityProofContext {
    /// Deserializes a grouped ciphertext 3-handles validity proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &Uint8Array,
    ) -> Result<GroupedCiphertext3HandlesValidityProofContext, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize = std::mem::size_of::<
            grouped_ciphertext_validity::GroupedCiphertext3HandlesValidityProofContext,
        >();
        if bytes.length() as usize != EXPECTED_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for GroupedCiphertext3HandlesValidityProofContext: expected {}, got {}",
                EXPECTED_LEN,
                bytes.length()
            )));
        }
        let mut data = [0u8; EXPECTED_LEN];
        bytes.copy_to(&mut data);
        bytemuck::try_from_bytes(&data)
            .map(|pod: &grouped_ciphertext_validity::GroupedCiphertext3HandlesValidityProofContext| Self { inner: *pod })
            .map_err(|_| {
                JsValue::from_str("Invalid bytes for GroupedCiphertext3HandlesValidityProofContext")
            })
    }

    /// Serializes the grouped ciphertext 3-handles validity proof context to a byte array.
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
    fn test_grouped_ciphertext_3_handles_validity_proof_creation_and_verification() {
        let first_keypair = ElGamalKeypair::new_rand();
        let second_keypair = ElGamalKeypair::new_rand();
        let third_keypair = ElGamalKeypair::new_rand();
        let amount: u64 = 55;
        let opening = PedersenOpening::new_rand();

        let grouped_ciphertext = GroupedElGamalCiphertext3Handles {
            inner: GroupedElGamal::encrypt_with(
                [
                    &first_keypair.pubkey().inner,
                    &second_keypair.pubkey().inner,
                    &third_keypair.pubkey().inner,
                ],
                amount,
                &opening.inner,
            ),
        };

        let proof = GroupedCiphertext3HandlesValidityProofData::new(
            &first_keypair.pubkey(),
            &second_keypair.pubkey(),
            &third_keypair.pubkey(),
            &grouped_ciphertext,
            amount,
            &opening,
        )
        .unwrap();

        assert!(proof.verify().is_ok());
    }

    #[wasm_bindgen_test]
    fn test_grouped_ciphertext_3_handles_validity_proof_bytes_roundtrip() {
        let first_keypair = ElGamalKeypair::new_rand();
        let second_keypair = ElGamalKeypair::new_rand();
        let third_keypair = ElGamalKeypair::new_rand();
        let amount: u64 = 55;
        let opening = PedersenOpening::new_rand();

        let grouped_ciphertext = GroupedElGamalCiphertext3Handles {
            inner: GroupedElGamal::encrypt_with(
                [
                    &first_keypair.pubkey().inner,
                    &second_keypair.pubkey().inner,
                    &third_keypair.pubkey().inner,
                ],
                amount,
                &opening.inner,
            ),
        };

        let proof = GroupedCiphertext3HandlesValidityProofData::new(
            &first_keypair.pubkey(),
            &second_keypair.pubkey(),
            &third_keypair.pubkey(),
            &grouped_ciphertext,
            amount,
            &opening,
        )
        .unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof = GroupedCiphertext3HandlesValidityProofData::from_bytes(
            &Uint8Array::from(bytes.as_slice()),
        )
        .unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        let context = proof.context();
        let context_bytes = context.to_bytes();
        let recovered_context = GroupedCiphertext3HandlesValidityProofContext::from_bytes(
            &Uint8Array::from(context_bytes.as_slice()),
        )
        .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }
}
