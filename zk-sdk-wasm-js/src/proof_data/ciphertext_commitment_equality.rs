use {
    crate::encryption::{
        elgamal::{WasmElGamalCiphertext, WasmElGamalKeypair, WasmElGamalPubkey},
        pedersen::{WasmPedersenCommitment, WasmPedersenOpening},
    },
    js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{
        ciphertext_commitment_equality::{
            CiphertextCommitmentEqualityProofContext, CiphertextCommitmentEqualityProofData,
        },
        ZkProofData,
    },
    wasm_bindgen::prelude::*,
};

/// A ciphertext-commitment equality proof. This proof certifies that an ElGamal
/// ciphertext and a Pedersen commitment encrypt/encode the same message.
#[wasm_bindgen(js_name = "CiphertextCommitmentEqualityProof")]
pub struct WasmCiphertextCommitmentEqualityProofData {
    pub(crate) inner: CiphertextCommitmentEqualityProofData,
}

crate::conversion::impl_inner_conversion!(
    WasmCiphertextCommitmentEqualityProofData,
    CiphertextCommitmentEqualityProofData
);

#[wasm_bindgen]
impl WasmCiphertextCommitmentEqualityProofData {
    /// Creates a new ciphertext-commitment equality proof.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keypair: &WasmElGamalKeypair,
        ciphertext: &WasmElGamalCiphertext,
        commitment: &WasmPedersenCommitment,
        opening: &WasmPedersenOpening,
        amount: u64,
    ) -> Result<WasmCiphertextCommitmentEqualityProofData, JsValue> {
        CiphertextCommitmentEqualityProofData::new(
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
    pub fn context(&self) -> WasmCiphertextCommitmentEqualityProofContext {
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
    ) -> Result<WasmCiphertextCommitmentEqualityProofData, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize = std::mem::size_of::<CiphertextCommitmentEqualityProofData>();
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
            .map(|pod: &CiphertextCommitmentEqualityProofData| Self { inner: *pod })
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
pub struct WasmCiphertextCommitmentEqualityProofContext {
    pub(crate) inner: CiphertextCommitmentEqualityProofContext,
}

crate::conversion::impl_inner_conversion!(
    WasmCiphertextCommitmentEqualityProofContext,
    CiphertextCommitmentEqualityProofContext
);

#[wasm_bindgen]
impl WasmCiphertextCommitmentEqualityProofContext {
    /// Deserializes a ciphertext-commitment equality proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &Uint8Array,
    ) -> Result<WasmCiphertextCommitmentEqualityProofContext, JsValue> {
        let expected_len = std::mem::size_of::<CiphertextCommitmentEqualityProofContext>();
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
            .map(|pod: &CiphertextCommitmentEqualityProofContext| Self { inner: *pod })
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
        let keypair = WasmElGamalKeypair::new_rand();
        let amount: u64 = 55;

        let ciphertext = keypair.pubkey().encrypt_u64(amount);
        let opening = WasmPedersenOpening::new_rand();
        let commitment = WasmPedersenCommitment::with_u64(amount, &opening);

        let proof = WasmCiphertextCommitmentEqualityProofData::new(
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
        let keypair = WasmElGamalKeypair::new_rand();
        let amount: u64 = 55;

        let ciphertext = keypair.pubkey().encrypt_u64(amount);
        let opening = WasmPedersenOpening::new_rand();
        let commitment = WasmPedersenCommitment::with_u64(amount, &opening);

        let proof = WasmCiphertextCommitmentEqualityProofData::new(
            &keypair,
            &ciphertext,
            &commitment,
            &opening,
            amount,
        )
        .unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof = WasmCiphertextCommitmentEqualityProofData::from_bytes(
            &Uint8Array::from(bytes.as_slice()),
        )
        .unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        let context = proof.context();
        let context_bytes = context.to_bytes();
        let recovered_context = WasmCiphertextCommitmentEqualityProofContext::from_bytes(
            &Uint8Array::from(context_bytes.as_slice()),
        )
        .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }
}
