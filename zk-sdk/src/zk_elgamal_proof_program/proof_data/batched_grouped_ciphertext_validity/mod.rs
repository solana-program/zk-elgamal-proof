mod handles_2;
mod handles_3;

#[cfg(not(target_os = "solana"))]
pub use {
    handles_2::new_batched_grouped_ciphertext_2_handles_validity_proof_data,
    handles_3::new_batched_grouped_ciphertext_3_handles_validity_proof_data,
};
pub use {
    handles_2::{
        BatchedGroupedCiphertext2HandlesValidityProofContext,
        BatchedGroupedCiphertext2HandlesValidityProofData,
    },
    handles_3::{
        BatchedGroupedCiphertext3HandlesValidityProofContext,
        BatchedGroupedCiphertext3HandlesValidityProofData,
    },
};
