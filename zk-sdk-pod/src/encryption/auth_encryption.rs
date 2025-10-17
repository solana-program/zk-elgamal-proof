//! Plain Old Data types for the AES128-GCM-SIV authenticated encryption scheme.

use {
    crate::{
        encryption::AE_CIPHERTEXT_LEN,
        macros::{impl_from_bytes, impl_from_str},
    },
    base64::{prelude::BASE64_STANDARD, Engine},
    bytemuck::{Pod, Zeroable},
    std::fmt,
};

/// Maximum length of a base64 encoded authenticated encryption ciphertext
const AE_CIPHERTEXT_MAX_BASE64_LEN: usize = 48;

/// The `AeCiphertext` type as a `Pod`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodAeCiphertext(pub [u8; AE_CIPHERTEXT_LEN]);

// `PodAeCiphertext` is a wrapper type for a byte array, which is both `Pod` and `Zeroable`. However,
// the marker traits `bytemuck::Pod` and `bytemuck::Zeroable` can only be derived for power-of-two
// length byte arrays. Directly implement these traits for `PodAeCiphertext`.
unsafe impl Zeroable for PodAeCiphertext {}
unsafe impl Pod for PodAeCiphertext {}

impl fmt::Debug for PodAeCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for PodAeCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodAeCiphertext,
    BYTES_LEN = AE_CIPHERTEXT_LEN,
    BASE64_LEN = AE_CIPHERTEXT_MAX_BASE64_LEN
);

impl_from_bytes!(TYPE = PodAeCiphertext, BYTES_LEN = AE_CIPHERTEXT_LEN);

impl Default for PodAeCiphertext {
    fn default() -> Self {
        Self::zeroed()
    }
}
