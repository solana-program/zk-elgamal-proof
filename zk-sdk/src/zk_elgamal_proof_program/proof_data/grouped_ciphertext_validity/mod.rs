mod handles_2;
mod handles_3;

#[cfg(not(target_os = "solana"))]
pub use {
    handles_2::GroupedCiphertext2HandlesValidityProofDataExt,
    handles_3::GroupedCiphertext3HandlesValidityProofDataExt,
};
