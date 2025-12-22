//! Plain Old Data types for the ElGamal encryption scheme.

use {
    crate::{
        encryption::{DECRYPT_HANDLE_LEN, ELGAMAL_CIPHERTEXT_LEN, ELGAMAL_PUBKEY_LEN},
        macros::{impl_from_bytes, impl_from_str},
    },
    base64::{prelude::BASE64_STANDARD, Engine},
    bytemuck::Zeroable,
    std::fmt,
};

/// Maximum length of a base64 encoded ElGamal public key
const ELGAMAL_PUBKEY_MAX_BASE64_LEN: usize = 44;

/// Maximum length of a base64 encoded ElGamal ciphertext
const ELGAMAL_CIPHERTEXT_MAX_BASE64_LEN: usize = 88;

/// Maximum length of a base64 encoded ElGamal decrypt handle
const DECRYPT_HANDLE_MAX_BASE64_LEN: usize = 44;

/// The `ElGamalCiphertext` type as a `Pod`.
#[derive(Clone, Copy, bytemuck_derive::Pod, bytemuck_derive::Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodElGamalCiphertext(pub [u8; ELGAMAL_CIPHERTEXT_LEN]);

impl fmt::Debug for PodElGamalCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for PodElGamalCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl Default for PodElGamalCiphertext {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl_from_str!(
    TYPE = PodElGamalCiphertext,
    BYTES_LEN = ELGAMAL_CIPHERTEXT_LEN,
    BASE64_LEN = ELGAMAL_CIPHERTEXT_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodElGamalCiphertext,
    BYTES_LEN = ELGAMAL_CIPHERTEXT_LEN
);

/// The `ElGamalPubkey` type as a `Pod`.
#[derive(Clone, Copy, Default, bytemuck_derive::Pod, bytemuck_derive::Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodElGamalPubkey(pub [u8; ELGAMAL_PUBKEY_LEN]);

impl fmt::Debug for PodElGamalPubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for PodElGamalPubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodElGamalPubkey,
    BYTES_LEN = ELGAMAL_PUBKEY_LEN,
    BASE64_LEN = ELGAMAL_PUBKEY_MAX_BASE64_LEN
);

impl_from_bytes!(TYPE = PodElGamalPubkey, BYTES_LEN = ELGAMAL_PUBKEY_LEN);

/// The `DecryptHandle` type as a `Pod`.
#[derive(Clone, Copy, Default, bytemuck_derive::Pod, bytemuck_derive::Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodDecryptHandle(pub [u8; DECRYPT_HANDLE_LEN]);

impl fmt::Debug for PodDecryptHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for PodDecryptHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodDecryptHandle,
    BYTES_LEN = DECRYPT_HANDLE_LEN,
    BASE64_LEN = DECRYPT_HANDLE_MAX_BASE64_LEN
);

impl_from_bytes!(TYPE = PodDecryptHandle, BYTES_LEN = DECRYPT_HANDLE_LEN);
