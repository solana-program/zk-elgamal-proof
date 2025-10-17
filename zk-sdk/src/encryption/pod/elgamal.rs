//! Plain Old Data types for the ElGamal encryption scheme.

use solana_zk_sdk_pod::encryption::elgamal::{
    PodDecryptHandle, PodElGamalCiphertext, PodElGamalPubkey,
};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::elgamal::{DecryptHandle, ElGamalCiphertext, ElGamalPubkey},
        errors::ElGamalError,
    },
    // curve25519_dalek::ristretto::CompressedRistretto,
};

#[cfg(not(target_os = "solana"))]
impl From<ElGamalCiphertext> for PodElGamalCiphertext {
    fn from(decoded_ciphertext: ElGamalCiphertext) -> Self {
        Self(decoded_ciphertext.to_bytes())
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<PodElGamalCiphertext> for ElGamalCiphertext {
    type Error = ElGamalError;

    fn try_from(pod_ciphertext: PodElGamalCiphertext) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod_ciphertext.0).ok_or(ElGamalError::CiphertextDeserialization)
    }
}

#[cfg(not(target_os = "solana"))]
impl From<ElGamalPubkey> for PodElGamalPubkey {
    fn from(decoded_pubkey: ElGamalPubkey) -> Self {
        Self(decoded_pubkey.into())
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<PodElGamalPubkey> for ElGamalPubkey {
    type Error = ElGamalError;

    fn try_from(pod_pubkey: PodElGamalPubkey) -> Result<Self, Self::Error> {
        Self::try_from(pod_pubkey.0.as_slice())
    }
}

#[cfg(not(target_os = "solana"))]
impl From<DecryptHandle> for PodDecryptHandle {
    fn from(decoded_handle: DecryptHandle) -> Self {
        Self(decoded_handle.to_bytes())
    }
}

// // For proof verification, interpret pod::DecryptHandle as CompressedRistretto
// #[cfg(not(target_os = "solana"))]
// impl From<PodDecryptHandle> for CompressedRistretto {
//     fn from(pod_handle: PodDecryptHandle) -> Self {
//         Self(pod_handle.0)
//     }
// }

#[cfg(not(target_os = "solana"))]
impl TryFrom<PodDecryptHandle> for DecryptHandle {
    type Error = ElGamalError;

    fn try_from(pod_handle: PodDecryptHandle) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod_handle.0).ok_or(ElGamalError::CiphertextDeserialization)
    }
}

// impl fmt::Display for PodDecryptHandle {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "{}", BASE64_STANDARD.encode(self.0))
//     }
// }

#[cfg(test)]
mod tests {
    use {super::*, crate::encryption::elgamal::ElGamalKeypair, std::str::FromStr};

    #[test]
    fn elgamal_pubkey_fromstr() {
        let elgamal_keypair = ElGamalKeypair::new_rand();
        let expected_elgamal_pubkey: PodElGamalPubkey = (*elgamal_keypair.pubkey()).into();

        let elgamal_pubkey_base64_str = format!("{}", expected_elgamal_pubkey);
        let computed_elgamal_pubkey =
            PodElGamalPubkey::from_str(&elgamal_pubkey_base64_str).unwrap();

        assert_eq!(expected_elgamal_pubkey, computed_elgamal_pubkey);
    }

    #[test]
    fn elgamal_ciphertext_fromstr() {
        let elgamal_keypair = ElGamalKeypair::new_rand();
        let expected_elgamal_ciphertext: PodElGamalCiphertext =
            elgamal_keypair.pubkey().encrypt(0_u64).into();

        let elgamal_ciphertext_base64_str = format!("{}", expected_elgamal_ciphertext);
        let computed_elgamal_ciphertext =
            PodElGamalCiphertext::from_str(&elgamal_ciphertext_base64_str).unwrap();

        assert_eq!(expected_elgamal_ciphertext, computed_elgamal_ciphertext);
    }
}
