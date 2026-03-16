//! The `solana-zk-sdk` crate contains tools to create and verify zero-knowledge proofs on
//! encrypted data.

// The warning `clippy::op_ref` is disabled to allow efficient operator arithmetic of structs that
// implement the `Copy` trait.
//
// ```
// let opening_0: PedersenOpening = PedersenOpening::new_rand();
// let opening_1: PedersenOpening = PedersenOpening::new_rand();
//
// // since PedersenOpening implement `Copy`, `opening_0` and `opening_1` will be copied as
// // parameters before `opening_sum` is computed.
// let opening_sum = opening_0 + opening_1;
//
// // if passed in as references, the extra copies will not occur
// let opening_sum = &opening_0 + &opening_1;
// ```
//
// `clippy::op_ref` is turned off to prevent clippy from warning that this is not idiomatic code.
#![allow(clippy::arithmetic_side_effects, clippy::op_ref)]

pub mod encryption;
pub mod errors;
#[doc(hidden)]
mod range_proof;
mod sigma_proofs;
pub mod transcript;
pub mod zk_elgamal_proof_program;

/// Global transcript domain separator.
///
/// This string MUST be changed for any fork or separate deployment to prevent
/// cross-chain proof replay attacks.
pub const TRANSCRIPT_DOMAIN: &[u8] = b"solana-zk-elgamal-proof-program-v1";
