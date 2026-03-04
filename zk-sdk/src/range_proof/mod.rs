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

use crate::{RISTRETTO_POINT_LEN, SCALAR_LEN};

pub mod errors;
pub mod pod;

#[cfg(not(target_os = "solana"))]
pub mod generators;
#[cfg(not(target_os = "solana"))]
pub mod inner_product;
#[cfg(not(target_os = "solana"))]
pub mod range;
#[cfg(not(target_os = "solana"))]
pub mod util;

#[cfg(not(target_os = "solana"))]
pub use range::*;

/// Byte length of a range proof excluding the inner-product proof component
pub const RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN: usize =
    5 * RISTRETTO_POINT_LEN + 2 * SCALAR_LEN;

/// Byte length of an inner-product proof for a vector of length 64
pub const INNER_PRODUCT_PROOF_U64_LEN: usize = 448;

/// Byte length of a range proof for an unsigned 64-bit number
pub const RANGE_PROOF_U64_LEN: usize =
    INNER_PRODUCT_PROOF_U64_LEN + RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN; // 672 bytes

/// Byte length of an inner-product proof for a vector of length 128
pub const INNER_PRODUCT_PROOF_U128_LEN: usize = 512;

/// Byte length of a range proof for an unsigned 128-bit number
pub const RANGE_PROOF_U128_LEN: usize =
    INNER_PRODUCT_PROOF_U128_LEN + RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN; // 736 bytes

/// Byte length of an inner-product proof for a vector of length 256
pub const INNER_PRODUCT_PROOF_U256_LEN: usize = 576;

/// Byte length of a range proof for an unsigned 256-bit number
pub const RANGE_PROOF_U256_LEN: usize =
    INNER_PRODUCT_PROOF_U256_LEN + RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN; // 800 bytes
