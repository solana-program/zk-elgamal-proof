//! The batched range proof instructions.
//!
//! A batched range proof is a cryptographic method that proves a set of committed values
//! fall within specified bit-ranges, without revealing the values themselves. It is more
//! efficient than verifying individual range proofs for each commitment.
//!
//! This module provides three instructions for batched range proofs, each corresponding to a
//! different total bit length:
//! - `VerifyBatchedRangeProofU64`: For proofs where the sum of bit lengths is 64.
//! - `VerifyBatchedRangeProofU128`: For proofs where the sum of bit lengths is 128.
//! - `VerifyBatchedRangeProofU256`: For proofs where the sum of bit lengths is 256.
//!
//! For example, to generate a batched range proof for a sequence of commitments `[C_1, C_2, C_3]`
//! with corresponding bit-lengths `[32, 32, 64]`, one must use `VerifyBatchedRangeProofU128`,
//! since the sum of bit-lengths is `32 + 32 + 64 = 128`.
//!
//! A proof must contain between 1 and 8 active commitments. Each active component's bit length
//! must be in `1..=64`, and their sum must equal the chosen instruction's 64-, 128-, or 256-bit
//! total. These totals do not increase the individual component limit: a `U128` proof can use
//! `[64, 64]`, but cannot use `[128]`.
//!
//! Active commitments occupy consecutive slots at the start of the context. Any unused trailing
//! slots must contain all-zero commitment encodings and zero bit lengths. These slots are padding
//! and do not contribute to the aggregate bit length. A zero bit length is invalid for an active
//! component. SDK proof builders accept only active components and add the padding automatically.

use solana_zk_sdk_pod::encryption::pedersen::PodPedersenCommitment;

pub mod batched_range_proof_u128;
pub mod batched_range_proof_u256;
pub mod batched_range_proof_u64;

pub use {batched_range_proof_u128::*, batched_range_proof_u256::*, batched_range_proof_u64::*};

/// The maximum number of Pedersen commitments that can be processed in a single batched range proof.
pub const MAX_COMMITMENTS: usize = 8;

/// The context data needed to verify a range-proof for a Pedersen committed value.
///
/// This struct holds the public information that a batched range proof certifies. It includes the
/// Pedersen commitments and their corresponding bit lengths. This context is shared by all
/// `VerifyBatchedRangeProofU{N}` instructions. Active component bit lengths must be in `1..=64`
/// and sum to the instruction's total of 64, 128, or 256 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck_derive::Pod, bytemuck_derive::Zeroable)]
#[repr(C)]
pub struct BatchedRangeProofContext {
    /// Between 1 and 8 consecutive nonzero commitment encodings, followed by all-zero padding.
    pub commitments: [PodPedersenCommitment; MAX_COMMITMENTS],
    /// Bit lengths in `1..=64` for active commitments, followed by zeros for unused slots.
    pub bit_lengths: [u8; MAX_COMMITMENTS],
}
