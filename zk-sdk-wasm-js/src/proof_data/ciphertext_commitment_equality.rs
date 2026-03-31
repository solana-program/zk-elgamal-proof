use {
    crate::encryption::{
        elgamal::{ElGamalCiphertext, ElGamalKeypair},
        pedersen::{PedersenCommitment, PedersenOpening},
    },
    js_sys::Uint8Array,
    solana_zk_elgamal_proof_interface::proof_data,
    solana_zk_sdk::zk_elgamal_proof_program::{self, VerifyZkProof},
    wasm_bindgen::prelude::*,
};

/// A ciphertext-commitment equality proof. This proof certifies that an ElGamal
/// ciphertext and a Pedersen commitment encrypt/encode the same message.
#[wasm_bindgen]
pub struct CiphertextCommitmentEqualityProofData {
    pub(crate) inner: proof_data::CiphertextCommitmentEqualityProofData,
}

crate::conversion::impl_inner_conversion!(
    CiphertextCommitmentEqualityProofData,
    proof_data::CiphertextCommitmentEqualityProofData
);

#[wasm_bindgen]
impl CiphertextCommitmentEqualityProofData {
    /// Creates a new ciphertext-commitment equality proof.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keypair: &ElGamalKeypair,
        ciphertext: &ElGamalCiphertext,
        commitment: &PedersenCommitment,
        opening: &PedersenOpening,
        amount: u64,
    ) -> Result<CiphertextCommitmentEqualityProofData, JsValue> {
        zk_elgamal_proof_program::build_ciphertext_commitment_equality_proof_data(
            &keypair.inner,
            &ciphertext.inner,
            &commitment.inner,
            &opening.inner,
            amount,
        )
        .map(|inner| Self { inner })
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the context data associated with the proof.
    #[wasm_bindgen]
    pub fn context(&self) -> CiphertextCommitmentEqualityProofContext {
        self.inner.context.into()
    }

    /// Verifies the ciphertext-commitment equality proof.
    /// Throws an error if the proof is invalid.
    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify_proof()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes a ciphertext-commitment equality proof from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &Uint8Array,
    ) -> Result<CiphertextCommitmentEqualityProofData, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize =
            std::mem::size_of::<proof_data::CiphertextCommitmentEqualityProofData>();
        if bytes.length() as usize != EXPECTED_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for CiphertextCommitmentEqualityProof: expected {}, got {}",
                EXPECTED_LEN,
                bytes.length()
            )));
        }

        let mut data = [0u8; EXPECTED_LEN];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &proof_data::CiphertextCommitmentEqualityProofData| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for CiphertextCommitmentEqualityProof"))
    }

    /// Serializes the ciphertext-commitment equality proof to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

/// The context data needed to verify a ciphertext-commitment equality proof.
#[wasm_bindgen]
pub struct CiphertextCommitmentEqualityProofContext {
    pub(crate) inner: proof_data::CiphertextCommitmentEqualityProofContext,
}

crate::conversion::impl_inner_conversion!(
    CiphertextCommitmentEqualityProofContext,
    proof_data::CiphertextCommitmentEqualityProofContext
);

#[wasm_bindgen]
impl CiphertextCommitmentEqualityProofContext {
    /// Deserializes a ciphertext-commitment equality proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &Uint8Array,
    ) -> Result<CiphertextCommitmentEqualityProofContext, JsValue> {
        let expected_len =
            std::mem::size_of::<proof_data::CiphertextCommitmentEqualityProofContext>();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for CiphertextCommitmentEqualityProofContext: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }
        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);
        bytemuck::try_from_bytes(&data)
            .map(|pod: &proof_data::CiphertextCommitmentEqualityProofContext| Self { inner: *pod })
            .map_err(|_| {
                JsValue::from_str("Invalid bytes for CiphertextCommitmentEqualityProofContext")
            })
    }

    /// Serializes the ciphertext-commitment equality proof context to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_ciphertext_commitment_equality_proof_creation_and_verification() {
        let keypair = ElGamalKeypair::new_rand();
        let amount: u64 = 55;

        let ciphertext = keypair.pubkey().encrypt_u64(amount);
        let opening = PedersenOpening::new_rand();
        let commitment = PedersenCommitment::with_u64(amount, &opening);

        let proof = CiphertextCommitmentEqualityProofData::new(
            &keypair,
            &ciphertext,
            &commitment,
            &opening,
            amount,
        )
        .unwrap();

        assert!(proof.verify().is_ok());
    }

    #[wasm_bindgen_test]
    fn test_ciphertext_commitment_equality_proof_bytes_roundtrip() {
        let keypair = ElGamalKeypair::new_rand();
        let amount: u64 = 55;

        let ciphertext = keypair.pubkey().encrypt_u64(amount);
        let opening = PedersenOpening::new_rand();
        let commitment = PedersenCommitment::with_u64(amount, &opening);

        let proof = CiphertextCommitmentEqualityProofData::new(
            &keypair,
            &ciphertext,
            &commitment,
            &opening,
            amount,
        )
        .unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof =
            CiphertextCommitmentEqualityProofData::from_bytes(&Uint8Array::from(bytes.as_slice()))
                .unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        let context = proof.context();
        let context_bytes = context.to_bytes();
        let recovered_context = CiphertextCommitmentEqualityProofContext::from_bytes(
            &Uint8Array::from(context_bytes.as_slice()),
        )
        .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }
}
