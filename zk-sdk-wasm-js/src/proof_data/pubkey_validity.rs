use {
    crate::encryption::elgamal::{WasmElGamalKeypair, WasmElGamalPubkey},
    js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{
        pubkey_validity::{PubkeyValidityProofContext, PubkeyValidityProofData},
        ZkProofData,
    },
    wasm_bindgen::prelude::*,
};

/// A public-key validity proof. This proof is used to certify that an ElGamal
/// public key is valid (i.e., the prover knows the corresponding secret key).
#[wasm_bindgen(js_name = "PubkeyValidityProof")]
pub struct WasmPubkeyValidityProofData {
    pub(crate) inner: PubkeyValidityProofData,
}

crate::conversion::impl_inner_conversion!(WasmPubkeyValidityProofData, PubkeyValidityProofData);

#[wasm_bindgen]
impl WasmPubkeyValidityProofData {
    /// Creates a new public-key validity proof.
    #[wasm_bindgen(constructor)]
    pub fn new(keypair: &WasmElGamalKeypair) -> Result<WasmPubkeyValidityProofData, JsValue> {
        PubkeyValidityProofData::new(&keypair.inner)
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the context data associated with the proof.
    #[wasm_bindgen]
    pub fn context(&self) -> WasmPubkeyValidityProofContext {
        self.inner.context.into()
    }

    /// Verifies the public-key validity proof.
    /// Throws an error if the proof is invalid.
    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify_proof()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes a pubkey validity proof from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<WasmPubkeyValidityProofData, JsValue> {
        let expected_len = std::mem::size_of::<PubkeyValidityProofData>();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for PubkeyValidityProof: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }

        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &PubkeyValidityProofData| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for PubkeyValidityProof"))
    }

    /// Serializes the pubkey validity proof to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

/// The context data needed to verify a public-key validity proof.
#[wasm_bindgen]
pub struct WasmPubkeyValidityProofContext {
    pub(crate) inner: PubkeyValidityProofContext,
}

crate::conversion::impl_inner_conversion!(
    WasmPubkeyValidityProofContext,
    PubkeyValidityProofContext
);

#[wasm_bindgen]
impl WasmPubkeyValidityProofContext {
    /// Deserializes a public-key validity proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<WasmPubkeyValidityProofContext, JsValue> {
        let expected_len = std::mem::size_of::<PubkeyValidityProofContext>();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for PubkeyValidityProofContext: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }
        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);
        bytemuck::try_from_bytes(&data)
            .map(|pod: &PubkeyValidityProofContext| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for PubkeyValidityProofContext"))
    }

    /// Serializes the public-key validity proof context to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_pubkey_validity_proof_creation_and_verification() {
        let keypair = WasmElGamalKeypair::new_rand();
        let proof = WasmPubkeyValidityProofData::new(&keypair).unwrap();
        assert!(proof.verify().is_ok());
    }

    #[wasm_bindgen_test]
    fn test_pubkey_validity_proof_bytes_roundtrip() {
        let keypair = WasmElGamalKeypair::new_rand();
        let proof = WasmPubkeyValidityProofData::new(&keypair).unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof =
            WasmPubkeyValidityProofData::from_bytes(&Uint8Array::from(bytes.as_slice())).unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        let context = proof.context();
        let context_bytes = context.to_bytes();
        let recovered_context =
            WasmPubkeyValidityProofContext::from_bytes(&Uint8Array::from(context_bytes.as_slice()))
                .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }
}
