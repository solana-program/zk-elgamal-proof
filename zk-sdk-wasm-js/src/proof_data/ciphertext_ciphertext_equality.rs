use {
    crate::encryption::{
        elgamal::{WasmElGamalCiphertext, WasmElGamalKeypair, WasmElGamalPubkey},
        pedersen::WasmPedersenOpening,
    },
    js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{
        ciphertext_ciphertext_equality::{
            CiphertextCiphertextEqualityProofContext, CiphertextCiphertextEqualityProofData,
        },
        ZkProofData,
    },
    wasm_bindgen::prelude::*,
};

/// A ciphertext-ciphertext equality proof. This proof certifies that two ElGamal
/// ciphertexts encrypt the same message.
#[wasm_bindgen(js_name = "CiphertextCiphertextEqualityProof")]
pub struct WasmCiphertextCiphertextEqualityProofData {
    pub(crate) inner: CiphertextCiphertextEqualityProofData,
}

crate::conversion::impl_inner_conversion!(
    WasmCiphertextCiphertextEqualityProofData,
    CiphertextCiphertextEqualityProofData
);

#[wasm_bindgen]
impl WasmCiphertextCiphertextEqualityProofData {
    /// Creates a new ciphertext-ciphertext equality proof.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        first_keypair: &WasmElGamalKeypair,
        second_pubkey: &WasmElGamalPubkey,
        first_ciphertext: &WasmElGamalCiphertext,
        second_ciphertext: &WasmElGamalCiphertext,
        second_opening: &WasmPedersenOpening,
        amount: u64,
    ) -> Result<WasmCiphertextCiphertextEqualityProofData, JsValue> {
        CiphertextCiphertextEqualityProofData::new(
            &first_keypair.inner,
            &second_pubkey.inner,
            &first_ciphertext.inner,
            &second_ciphertext.inner,
            &second_opening.inner,
            amount,
        )
        .map(|inner| Self { inner })
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the context data associated with the proof.
    #[wasm_bindgen]
    pub fn context(&self) -> WasmCiphertextCiphertextEqualityProofContext {
        self.inner.context.into()
    }

    /// Verifies the ciphertext-ciphertext equality proof.
    /// Throws an error if the proof is invalid.
    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify_proof()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes a ciphertext-ciphertext equality proof from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &Uint8Array,
    ) -> Result<WasmCiphertextCiphertextEqualityProofData, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize = std::mem::size_of::<CiphertextCiphertextEqualityProofData>();
        if bytes.length() as usize != EXPECTED_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for CiphertextCiphertextEqualityProof: expected {}, got {}",
                EXPECTED_LEN,
                bytes.length()
            )));
        }

        let mut data = [0u8; EXPECTED_LEN];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &CiphertextCiphertextEqualityProofData| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for CiphertextCiphertextEqualityProof"))
    }

    /// Serializes the ciphertext-ciphertext equality proof to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

/// The context data needed to verify a ciphertext-ciphertext equality proof.
#[wasm_bindgen]
pub struct WasmCiphertextCiphertextEqualityProofContext {
    pub(crate) inner: CiphertextCiphertextEqualityProofContext,
}

crate::conversion::impl_inner_conversion!(
    WasmCiphertextCiphertextEqualityProofContext,
    CiphertextCiphertextEqualityProofContext
);

#[wasm_bindgen]
impl WasmCiphertextCiphertextEqualityProofContext {
    /// Deserializes a ciphertext-ciphertext equality proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &Uint8Array,
    ) -> Result<WasmCiphertextCiphertextEqualityProofContext, JsValue> {
        let expected_len = std::mem::size_of::<CiphertextCiphertextEqualityProofContext>();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for CiphertextCiphertextEqualityProofContext: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }
        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);
        bytemuck::try_from_bytes(&data)
            .map(|pod: &CiphertextCiphertextEqualityProofContext| Self { inner: *pod })
            .map_err(|_| {
                JsValue::from_str("Invalid bytes for CiphertextCiphertextEqualityProofContext")
            })
    }

    /// Serializes the ciphertext-ciphertext equality proof context to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_ciphertext_ciphertext_equality_proof_creation_and_verification() {
        let first_keypair = WasmElGamalKeypair::new_rand();
        let second_keypair = WasmElGamalKeypair::new_rand();
        let amount: u64 = 55;

        let first_ciphertext = first_keypair.pubkey().encrypt_u64(amount);
        let second_opening = WasmPedersenOpening::new_rand();
        let second_ciphertext = WasmElGamalCiphertext {
            inner: second_keypair
                .pubkey()
                .inner
                .encrypt_with(amount, &second_opening.inner),
        };

        let proof = WasmCiphertextCiphertextEqualityProofData::new(
            &first_keypair,
            &second_keypair.pubkey(),
            &first_ciphertext,
            &second_ciphertext,
            &second_opening,
            amount,
        )
        .unwrap();

        assert!(proof.verify().is_ok());
    }

    #[wasm_bindgen_test]
    fn test_ciphertext_ciphertext_equality_proof_bytes_roundtrip() {
        let first_keypair = WasmElGamalKeypair::new_rand();
        let second_keypair = WasmElGamalKeypair::new_rand();
        let amount: u64 = 55;

        let first_ciphertext = first_keypair.pubkey().encrypt_u64(amount);
        let second_opening = WasmPedersenOpening::new_rand();
        let second_ciphertext = WasmElGamalCiphertext {
            inner: second_keypair
                .pubkey()
                .inner
                .encrypt_with(amount, &second_opening.inner),
        };

        let proof = WasmCiphertextCiphertextEqualityProofData::new(
            &first_keypair,
            &second_keypair.pubkey(),
            &first_ciphertext,
            &second_ciphertext,
            &second_opening,
            amount,
        )
        .unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof = WasmCiphertextCiphertextEqualityProofData::from_bytes(
            &Uint8Array::from(bytes.as_slice()),
        )
        .unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        let context = proof.context();
        let context_bytes = context.to_bytes();
        let recovered_context = WasmCiphertextCiphertextEqualityProofContext::from_bytes(
            &Uint8Array::from(context_bytes.as_slice()),
        )
        .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }
}
