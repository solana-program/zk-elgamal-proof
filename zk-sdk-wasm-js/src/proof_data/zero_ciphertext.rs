use {
    crate::encryption::elgamal::{ElGamalCiphertext, ElGamalKeypair},
    js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{zero_ciphertext, ZkProofData},
    wasm_bindgen::prelude::*,
};

/// A zero-ciphertext proof. This proof is used to certify that an ElGamal
/// ciphertext encrypts the number 0.
#[wasm_bindgen]
pub struct ZeroCiphertextProofData {
    pub(crate) inner: zero_ciphertext::ZeroCiphertextProofData,
}

crate::conversion::impl_inner_conversion!(
    ZeroCiphertextProofData,
    zero_ciphertext::ZeroCiphertextProofData
);

#[wasm_bindgen]
impl ZeroCiphertextProofData {
    /// Creates a new zero-ciphertext proof.
    #[wasm_bindgen(constructor)]
    pub fn new(
        keypair: &ElGamalKeypair,
        ciphertext: &ElGamalCiphertext,
    ) -> Result<ZeroCiphertextProofData, JsValue> {
        zero_ciphertext::ZeroCiphertextProofData::new(&keypair.inner, &ciphertext.inner)
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the context data associated with the proof.
    #[wasm_bindgen]
    pub fn context(&self) -> ZeroCiphertextProofContext {
        self.inner.context.into()
    }

    /// Verifies the zero-ciphertext proof.
    /// Throws an error if the proof is invalid.
    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify_proof()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes a zero-ciphertext proof from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<ZeroCiphertextProofData, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize = std::mem::size_of::<zero_ciphertext::ZeroCiphertextProofData>();
        if bytes.length() as usize != EXPECTED_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for ZeroCiphertextProof: expected {}, got {}",
                EXPECTED_LEN,
                bytes.length()
            )));
        }

        let mut data = vec![0u8; EXPECTED_LEN];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &zero_ciphertext::ZeroCiphertextProofData| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for ZeroCiphertextProof"))
    }

    /// Serializes the zero-ciphertext proof to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

/// The context data needed to verify a zero-ciphertext proof.
#[wasm_bindgen]
pub struct ZeroCiphertextProofContext {
    pub(crate) inner: zero_ciphertext::ZeroCiphertextProofContext,
}

crate::conversion::impl_inner_conversion!(
    ZeroCiphertextProofContext,
    zero_ciphertext::ZeroCiphertextProofContext
);

#[wasm_bindgen]
impl ZeroCiphertextProofContext {
    /// Deserializes a zero-ciphertext proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<ZeroCiphertextProofContext, JsValue> {
        let expected_len = std::mem::size_of::<zero_ciphertext::ZeroCiphertextProofContext>();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for ZeroCiphertextProofContext: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }
        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);
        bytemuck::try_from_bytes(&data)
            .map(|pod: &zero_ciphertext::ZeroCiphertextProofContext| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for ZeroCiphertextProofContext"))
    }

    /// Serializes the zero-ciphertext proof context to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_zero_ciphertext_proof_creation_and_verification() {
        let keypair = ElGamalKeypair::new_rand();

        // Proof for a valid encryption of 0
        let zero_ciphertext = keypair.pubkey().encrypt_u64(0);
        let proof_valid = ZeroCiphertextProofData::new(&keypair, &zero_ciphertext).unwrap();
        assert!(proof_valid.verify().is_ok());

        // Proof for an invalid encryption of 1
        let one_ciphertext = keypair.pubkey().encrypt_u64(1);
        let result = ZeroCiphertextProofData::new(&keypair, &one_ciphertext);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_zero_ciphertext_proof_bytes_roundtrip() {
        let keypair = ElGamalKeypair::new_rand();
        let ciphertext = keypair.pubkey().encrypt_u64(0);
        let proof = ZeroCiphertextProofData::new(&keypair, &ciphertext).unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof =
            ZeroCiphertextProofData::from_bytes(&Uint8Array::from(bytes.as_slice())).unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        let context = proof.context();
        let context_bytes = context.to_bytes();
        let recovered_context =
            ZeroCiphertextProofContext::from_bytes(&Uint8Array::from(context_bytes.as_slice()))
                .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }
}
