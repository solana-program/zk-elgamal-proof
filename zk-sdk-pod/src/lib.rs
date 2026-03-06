pub mod encryption;
pub mod errors;
mod macros;
pub mod primitive_types;
pub mod range_proof;
pub mod sigma_proofs;

/// Byte length of a compressed Ristretto point or scalar in Curve25519
const UNIT_LEN: usize = 32;
/// Byte length of a compressed Ristretto point in Curve25519
const RISTRETTO_POINT_LEN: usize = UNIT_LEN;
/// Byte length of a scalar in Curve25519
const SCALAR_LEN: usize = UNIT_LEN;
