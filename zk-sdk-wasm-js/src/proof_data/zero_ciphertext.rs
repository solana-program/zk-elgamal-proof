use {
    crate::encryption::elgamal::{WasmElGamalCiphertext, WasmElGamalKeypair, WasmElGamalPubkey},
    js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{
        zero_ciphertext::{ZeroCiphertextProofContext, ZeroCiphertextProofData},
        ZkProofData,
    },
    wasm_bindgen::prelude::*,
};

/// A zero-ciphertext proof. This proof is used to certify that an ElGamal
/// ciphertext encrypts the number 0.
#[wasm_bindgen(js_name = "ZeroCiphertextProof")]
pub struct WasmZeroCiphertextProofData {
    pub(crate) inner: ZeroCiphertextProofData,
}

crate::conversion::impl_inner_conversion!(WasmZeroCiphertextProofData, ZeroCiphertextProofData);

#[wasm_bindgen]
impl WasmZeroCiphertextProofData {
    /// Creates a new zero-ciphertext proof.
    #[wasm_bindgen(constructor)]
    pub fn new(
        keypair: &WasmElGamalKeypair,
        ciphertext: &WasmElGamalCiphertext,
    ) -> Result<WasmZeroCiphertextProofData, JsValue> {
        ZeroCiphertextProofData::new(&keypair.inner, &ciphertext.inner)
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the context data associated with the proof.
    #[wasm_bindgen]
    pub fn context(&self) -> WasmZeroCiphertextProofContext {
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
    pub fn from_bytes(bytes: &Uint8Array) -> Result<WasmZeroCiphertextProofData, JsValue> {
        let expected_len = std::mem::size_of::<ZeroCiphertextProofData>();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for ZeroCiphertextProof: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }

        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &ZeroCiphertextProofData| Self { inner: *pod })
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
pub struct WasmZeroCiphertextProofContext {
    pub(crate) inner: ZeroCiphertextProofContext,
}

crate::conversion::impl_inner_conversion!(
    WasmZeroCiphertextProofContext,
    ZeroCiphertextProofContext
);

#[wasm_bindgen]
impl WasmZeroCiphertextProofContext {
    /// Deserializes a zero-ciphertext proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<WasmZeroCiphertextProofContext, JsValue> {
        let expected_len = std::mem::size_of::<ZeroCiphertextProofContext>();
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
            .map(|pod: &ZeroCiphertextProofContext| Self { inner: *pod })
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
        let keypair = WasmElGamalKeypair::new_rand();

        // Proof for a valid encryption of 0
        let zero_ciphertext = keypair.pubkey().encrypt_u64(0);
        let proof_valid = WasmZeroCiphertextProofData::new(&keypair, &zero_ciphertext).unwrap();
        assert!(proof_valid.verify().is_ok());

        // Proof for an invalid encryption of 1
        let one_ciphertext = keypair.pubkey().encrypt_u64(1);
        let proof_invalid = WasmZeroCiphertextProofData::new(&keypair, &one_ciphertext).unwrap();
        assert!(proof_invalid.verify().is_err());
    }

    #[wasm_bindgen_test]
    fn test_zero_ciphertext_proof_bytes_roundtrip() {
        let keypair = WasmElGamalKeypair::new_rand();
        let ciphertext = keypair.pubkey().encrypt_u64(0);
        let proof = WasmZeroCiphertextProofData::new(&keypair, &ciphertext).unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof =
            WasmZeroCiphertextProofData::from_bytes(&Uint8Array::from(bytes.as_slice())).unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        let context = proof.context();
        let context_bytes = context.to_bytes();
        let recovered_context =
            WasmZeroCiphertextProofContext::from_bytes(&Uint8Array::from(context_bytes.as_slice()))
                .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }
}
