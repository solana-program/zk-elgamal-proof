mod handles_2;
mod handles_3;

pub use {
    handles_2::{
        build_grouped_ciphertext_2_handles_validity_proof_data,
        GroupedCiphertext2HandlesValidityProofContext, GroupedCiphertext2HandlesValidityProofData,
    },
    handles_3::{
        build_grouped_ciphertext_3_handles_validity_proof_data,
        GroupedCiphertext3HandlesValidityProofContext, GroupedCiphertext3HandlesValidityProofData,
    },
};
