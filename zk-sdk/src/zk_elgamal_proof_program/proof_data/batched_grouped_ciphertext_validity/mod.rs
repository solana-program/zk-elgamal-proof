mod handles_2;
mod handles_3;

#[cfg(not(target_os = "solana"))]
pub use {
    handles_2::BatchedGroupedCiphertext2HandlesValidityProofDataExt,
    handles_3::BatchedGroupedCiphertext3HandlesValidityProofDataExt,
};
