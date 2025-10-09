use {
    crate::elgamal_wasm::WasmElGamalKeypair, js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::pubkey_validity::PubkeyValidityProofData,
    wasm_bindgen::prelude::*,
};

/// A public-key validity proof. This proof is used to certify that an ElGamal
/// public key is valid (i.e., the prover knows the corresponding secret key).
#[wasm_bindgen(js_name = "PubkeyValidityProof")]
pub struct WasmPubkeyValidityProofData {
    pub(crate) inner: PubkeyValidityProofData,
}

#[wasm_bindgen]
impl WasmPubkeyValidityProofData {
    /// Creates a new public-key validity proof.
    #[wasm_bindgen(constructor)]
    pub fn new(keypair: &WasmElGamalKeypair) -> Result<WasmPubkeyValidityProofData, JsValue> {
        PubkeyValidityProofData::new(&keypair.inner)
            .map(|inner| Self { inner })
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

#[cfg(test)]
mod tests {
    use {super::*, crate::elgamal_wasm::WasmElGamalKeypair, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_pubkey_validity_proof_creation() {
        let keypair = WasmElGamalKeypair::new_rand();
        let proof = WasmPubkeyValidityProofData::new(&keypair);
        assert!(proof.is_ok());
    }

    #[wasm_bindgen_test]
    fn test_pubkey_validity_proof_bytes_roundtrip() {
        let keypair = WasmElGamalKeypair::new_rand();
        let proof = WasmPubkeyValidityProofData::new(&keypair).unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof =
            WasmPubkeyValidityProofData::from_bytes(&Uint8Array::from(bytes.as_slice())).unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());
    }
}
