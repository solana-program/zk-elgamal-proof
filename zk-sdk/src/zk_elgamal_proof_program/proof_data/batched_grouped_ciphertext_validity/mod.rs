mod handles_2;
mod handles_3;

pub use {
    handles_2::{
        new_batched_grouped_ciphertext_2_handles_validity_proof_data,
        BatchedGroupedCiphertext2HandlesValidityProofContext,
        BatchedGroupedCiphertext2HandlesValidityProofData,
    },
    handles_3::{
        new_batched_grouped_ciphertext_3_handles_validity_proof_data,
        BatchedGroupedCiphertext3HandlesValidityProofContext,
        BatchedGroupedCiphertext3HandlesValidityProofData,
    },
};
