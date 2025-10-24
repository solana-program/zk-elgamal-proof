use {
    crate::encryption::elgamal::{ElGamalKeypair, ElGamalPubkey},
    js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{pubkey_validity, ZkProofData},
    wasm_bindgen::prelude::*,
};

/// A public-key validity proof. This proof is used to certify that an ElGamal
/// public key is valid (i.e., the prover knows the corresponding secret key).
#[wasm_bindgen]
pub struct PubkeyValidityProofData {
    pub(crate) inner: pubkey_validity::PubkeyValidityProofData,
}

crate::conversion::impl_inner_conversion!(
    PubkeyValidityProofData,
    pubkey_validity::PubkeyValidityProofData
);

#[wasm_bindgen]
impl PubkeyValidityProofData {
    /// Creates a new public-key validity proof.
    #[wasm_bindgen(constructor)]
    pub fn new(keypair: &ElGamalKeypair) -> Result<PubkeyValidityProofData, JsValue> {
        pubkey_validity::PubkeyValidityProofData::new(&keypair.inner)
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the context data associated with the proof.
    #[wasm_bindgen]
    pub fn context(&self) -> PubkeyValidityProofContext {
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
    pub fn from_bytes(bytes: &Uint8Array) -> Result<PubkeyValidityProofData, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize = std::mem::size_of::<pubkey_validity::PubkeyValidityProofData>();
        if bytes.length() as usize != EXPECTED_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for PubkeyValidityProof: expected {}, got {}",
                EXPECTED_LEN,
                bytes.length()
            )));
        }

        let mut data = [0u8; EXPECTED_LEN];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &pubkey_validity::PubkeyValidityProofData| Self { inner: *pod })
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
pub struct PubkeyValidityProofContext {
    pub(crate) inner: pubkey_validity::PubkeyValidityProofContext,
}

crate::conversion::impl_inner_conversion!(
    PubkeyValidityProofContext,
    pubkey_validity::PubkeyValidityProofContext
);

#[wasm_bindgen]
impl PubkeyValidityProofContext {
    /// Deserializes a public-key validity proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<PubkeyValidityProofContext, JsValue> {
        let expected_len = std::mem::size_of::<pubkey_validity::PubkeyValidityProofContext>();
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
            .map(|pod: &pubkey_validity::PubkeyValidityProofContext| Self { inner: *pod })
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
        let keypair = ElGamalKeypair::new_rand();
        let proof = PubkeyValidityProofData::new(&keypair).unwrap();
        assert!(proof.verify().is_ok());
    }

    #[wasm_bindgen_test]
    fn test_pubkey_validity_proof_bytes_roundtrip() {
        let keypair = ElGamalKeypair::new_rand();
        let proof = PubkeyValidityProofData::new(&keypair).unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof =
            PubkeyValidityProofData::from_bytes(&Uint8Array::from(bytes.as_slice())).unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        let context = proof.context();
        let context_bytes = context.to_bytes();
        let recovered_context =
            PubkeyValidityProofContext::from_bytes(&Uint8Array::from(context_bytes.as_slice()))
                .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }
}
