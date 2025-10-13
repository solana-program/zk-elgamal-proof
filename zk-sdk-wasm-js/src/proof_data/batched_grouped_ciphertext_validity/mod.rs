mod handles_2;
mod handles_3;

pub use {
    handles_2::{
        WasmBatchedGroupedCiphertext2HandlesValidityProofContext,
        WasmBatchedGroupedCiphertext2HandlesValidityProofData,
    },
    handles_3::{
        WasmBatchedGroupedCiphertext3HandlesValidityProofContext,
        WasmBatchedGroupedCiphertext3HandlesValidityProofData,
    },
};
