use {
    js_sys::Uint8Array,
    solana_zk_sdk::zk_elgamal_proof_program::proof_data::batched_range_proof::BatchedRangeProofContext,
    wasm_bindgen::prelude::*,
};

pub mod batched_range_proof_u128;
pub mod batched_range_proof_u256;
pub mod batched_range_proof_u64;

/// The context data for a batched range proof. This context is shared by all
/// batched range proof instructions.
#[wasm_bindgen(js_name = "BatchedRangeProofContext")]
pub struct WasmBatchedRangeProofContext {
    pub(crate) inner: BatchedRangeProofContext,
}

crate::conversion::impl_inner_conversion!(WasmBatchedRangeProofContext, BatchedRangeProofContext);

#[wasm_bindgen]
impl WasmBatchedRangeProofContext {
    /// Deserializes a batched range proof context from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<WasmBatchedRangeProofContext, JsValue> {
        let expected_len = std::mem::size_of::<BatchedRangeProofContext>();
        if bytes.length() as usize != expected_len {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for BatchedRangeProofContext: expected {}, got {}",
                expected_len,
                bytes.length()
            )));
        }

        let mut data = vec![0u8; expected_len];
        bytes.copy_to(&mut data);

        bytemuck::try_from_bytes(&data)
            .map(|pod: &BatchedRangeProofContext| Self { inner: *pod })
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
        let context = WasmBatchedRangeProofContext {
            inner: BatchedRangeProofContext::zeroed(),
        };

        let bytes = context.to_bytes();
        let recovered_context =
            WasmBatchedRangeProofContext::from_bytes(&Uint8Array::from(bytes.as_slice())).unwrap();

        assert_eq!(bytes, recovered_context.to_bytes());
    }
}
