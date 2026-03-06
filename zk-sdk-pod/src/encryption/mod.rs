use crate::{RISTRETTO_POINT_LEN, SCALAR_LEN};

pub mod auth_encryption;
pub mod elgamal;
pub mod grouped_elgamal;
pub mod pedersen;

/// Byte length of an authenticated encryption secret key
pub const AE_KEY_LEN: usize = 16;

/// Byte length of a complete authenticated encryption ciphertext component that includes the
/// ciphertext and nonce components
pub const AE_CIPHERTEXT_LEN: usize = 36;

/// Byte length of a decrypt handle
pub const DECRYPT_HANDLE_LEN: usize = RISTRETTO_POINT_LEN;

/// Byte length of an ElGamal ciphertext
pub const ELGAMAL_CIPHERTEXT_LEN: usize = PEDERSEN_COMMITMENT_LEN + DECRYPT_HANDLE_LEN;

/// Byte length of an ElGamal public key
pub const ELGAMAL_PUBKEY_LEN: usize = RISTRETTO_POINT_LEN;

/// Byte length of an ElGamal secret key
pub const ELGAMAL_SECRET_KEY_LEN: usize = SCALAR_LEN;

/// Byte length of an ElGamal keypair
pub const ELGAMAL_KEYPAIR_LEN: usize = ELGAMAL_PUBKEY_LEN + ELGAMAL_SECRET_KEY_LEN;

/// Byte length of a Pedersen opening.
pub const PEDERSEN_OPENING_LEN: usize = SCALAR_LEN;

/// Byte length of a Pedersen commitment.
pub const PEDERSEN_COMMITMENT_LEN: usize = RISTRETTO_POINT_LEN;
