// Copyright (c) 2018 Chain, Inc.
// This code is licensed under the MIT license.

//! The Bulletproofs range-proof implementation over Curve25519 Ristretto points.
//!
//! The implementation is based on the dalek-cryptography bulletproofs
//! [implementation](https://github.com/dalek-cryptography/bulletproofs). Compared to the original
//! implementation by dalek-cryptography:
//! - This implementation focuses on the range proof implementation, while the dalek-cryptography
//!   crate additionally implements the general bulletproofs implementation for languages that can be
//!   represented by arithmetic circuits as well as MPC.
//! - This implementation implements a non-interactive range proof aggregation that is specified in
//!   the original Bulletproofs [paper](https://eprint.iacr.org/2017/1066) (Section 4.3).

pub mod errors;

#[cfg(not(target_os = "solana"))]
pub mod generators;
#[cfg(not(target_os = "solana"))]
pub mod inner_product;
#[cfg(not(target_os = "solana"))]
pub mod range;
#[cfg(not(target_os = "solana"))]
pub mod util;
