use {
    js_sys::Uint8Array, solana_zk_sdk::zk_elgamal_proof_program::proof_data::batched_range_proof,
    wasm_bindgen::prelude::*,
};

pub mod batched_range_proof_u128;
pub mod batched_range_proof_u256;
pub mod batched_range_proof_u64;

/// The context data for a batched range proof. This context is shared by all
/// batched range proof instructions.
#[wasm_bindgen]
pub struct BatchedRangeProofContext {
    pub(crate) inner: batched_range_proof::BatchedRangeProofContext,
}

crate::conversion::impl_inner_conversion!(
    BatchedRangeProofContext,
    batched_range_proof::BatchedRangeProofContext
);

#[wasm_bindgen]
impl BatchedRangeProofContext {
    /// Deserializes a batched range proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<BatchedRangeProofContext, JsValue> {
        // Define expected length as a constant for stack allocation
        const EXPECTED_LEN: usize =
            std::mem::size_of::<batched_range_proof::BatchedRangeProofContext>();
        if bytes.length() as usize != EXPECTED_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for BatchedRangeProofContext: expected {}, got {}",
                EXPECTED_LEN,
                bytes.length()
            )));
        }

        let mut data = [0u8; EXPECTED_LEN];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &batched_range_proof::BatchedRangeProofContext| Self { inner: *pod })
            .map_err(|_| JsValue::from_str("Invalid bytes for BatchedRangeProofContext"))
    }

    /// Serializes the batched range proof context to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(&self.inner).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, bytemuck::Zeroable, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_batched_range_proof_context_bytes_roundtrip() {
        let context = BatchedRangeProofContext {
            inner: batched_range_proof::BatchedRangeProofContext::zeroed(),
        };

        let bytes = context.to_bytes();
        let recovered_context =
            BatchedRangeProofContext::from_bytes(&Uint8Array::from(bytes.as_slice())).unwrap();

        assert_eq!(bytes, recovered_context.to_bytes());
    }
}
