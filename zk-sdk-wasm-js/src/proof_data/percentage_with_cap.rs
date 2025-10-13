use {
    crate::encryption::pedersen::{WasmPedersenCommitment, WasmPedersenOpening},
    js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::{
        percentage_with_cap::{PercentageWithCapProofContext, PercentageWithCapProofData},
        ZkProofData,
    },
    wasm_bindgen::prelude::*,
};

/// A percentage-with-cap proof. This proof is used to certify that a transfer
/// amount is within a certain percentage of a base amount, with a cap.
#[wasm_bindgen(js_name = "PercentageWithCapProof")]
pub struct WasmPercentageWithCapProofData {
    pub(crate) inner: PercentageWithCapProofData,
}

crate::conversion::impl_inner_conversion!(
    WasmPercentageWithCapProofData,
    PercentageWithCapProofData
);

#[wasm_bindgen]
impl WasmPercentageWithCapProofData {
    /// Creates a new percentage-with-cap proof.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        percentage_commitment: &WasmPedersenCommitment,
        percentage_opening: &WasmPedersenOpening,
        percentage_amount: u64,
        delta_commitment: &WasmPedersenCommitment,
        delta_opening: &WasmPedersenOpening,
        delta_amount: u64,
        claimed_commitment: &WasmPedersenCommitment,
        claimed_opening: &WasmPedersenOpening,
        max_value: u64,
    ) -> Result<WasmPercentageWithCapProofData, JsValue> {
        PercentageWithCapProofData::new(
            &percentage_commitment.inner,
            &percentage_opening.inner,
            percentage_amount,
            &delta_commitment.inner,
            &delta_opening.inner,
            delta_amount,
            &claimed_commitment.inner,
            &claimed_opening.inner,
            max_value,
        )
        .map(|inner| Self { inner })
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the context data associated with the proof.
    #[wasm_bindgen]
    pub fn context(&self) -> WasmPercentageWithCapProofContext {
        self.inner.context.into()
    }

    /// Verifies the percentage-with-cap proof.
    /// Throws an error if the proof is invalid.
    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify_proof()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes a percentage-with-cap proof from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<WasmPercentageWithCapProofData, JsValue> {
        let expected_len = std::mem::size_of::<PercentageWithCapProofData>();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for PercentageWithCapProof: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }

        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &PercentageWithCapProofData| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for PercentageWithCapProof"))
    }

    /// Serializes the percentage-with-cap proof to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

/// The context data needed to verify a percentage-with-cap proof.
#[wasm_bindgen]
pub struct WasmPercentageWithCapProofContext {
    pub(crate) inner: PercentageWithCapProofContext,
}

crate::conversion::impl_inner_conversion!(
    WasmPercentageWithCapProofContext,
    PercentageWithCapProofContext
);

#[wasm_bindgen]
impl WasmPercentageWithCapProofContext {
    /// Deserializes a percentage-with-cap proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<WasmPercentageWithCapProofContext, JsValue> {
        let expected_len = std::mem::size_of::<PercentageWithCapProofContext>();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for PercentageWithCapProofContext: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }
        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);
        bytemuck::try_from_bytes(&data)
            .map(|pod: &PercentageWithCapProofContext| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for PercentageWithCapProofContext"))
    }

    /// Serializes the percentage-with-cap proof context to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_percentage_with_cap_proof_creation_and_verification() {
        let percentage_amount: u64 = 1;
        let delta_amount: u64 = 9600;
        let max_value: u64 = 3;

        let percentage_opening = WasmPedersenOpening::new_rand();
        let percentage_commitment =
            WasmPedersenCommitment::with_u64(percentage_amount, &percentage_opening);

        let delta_opening = WasmPedersenOpening::new_rand();
        let delta_commitment = WasmPedersenCommitment::with_u64(delta_amount, &delta_opening);

        let claimed_opening = WasmPedersenOpening::new_rand();
        let claimed_commitment = WasmPedersenCommitment::with_u64(delta_amount, &claimed_opening);

        let proof = WasmPercentageWithCapProofData::new(
            &percentage_commitment,
            &percentage_opening,
            percentage_amount,
            &delta_commitment,
            &delta_opening,
            delta_amount,
            &claimed_commitment,
            &claimed_opening,
            max_value,
        )
        .unwrap();

        assert!(proof.verify().is_ok());
    }

    #[wasm_bindgen_test]
    fn test_percentage_with_cap_proof_bytes_roundtrip() {
        let percentage_amount: u64 = 1;
        let delta_amount: u64 = 9600;
        let max_value: u64 = 3;

        let percentage_opening = WasmPedersenOpening::new_rand();
        let percentage_commitment =
            WasmPedersenCommitment::with_u64(percentage_amount, &percentage_opening);

        let delta_opening = WasmPedersenOpening::new_rand();
        let delta_commitment = WasmPedersenCommitment::with_u64(delta_amount, &delta_opening);

        let claimed_opening = WasmPedersenOpening::new_rand();
        let claimed_commitment = WasmPedersenCommitment::with_u64(delta_amount, &claimed_opening);

        let proof = WasmPercentageWithCapProofData::new(
            &percentage_commitment,
            &percentage_opening,
            percentage_amount,
            &delta_commitment,
            &delta_opening,
            delta_amount,
            &claimed_commitment,
            &claimed_opening,
            max_value,
        )
        .unwrap();

        let bytes = proof.to_bytes();
        let recovered_proof =
            WasmPercentageWithCapProofData::from_bytes(&Uint8Array::from(bytes.as_slice()))
                .unwrap();

        assert_eq!(proof.to_bytes(), recovered_proof.to_bytes());

        let context = proof.context();
        let context_bytes = context.to_bytes();
        let recovered_context = WasmPercentageWithCapProofContext::from_bytes(&Uint8Array::from(
            context_bytes.as_slice(),
        ))
        .unwrap();
        assert_eq!(context_bytes, recovered_context.to_bytes());
    }
}
