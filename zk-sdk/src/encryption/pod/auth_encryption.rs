//! Plain Old Data types for the AES128-GCM-SIV authenticated encryption scheme.

#[cfg(not(target_os = "solana"))]
use crate::{encryption::auth_encryption::AeCiphertext, errors::AuthenticatedEncryptionError};
use solana_zk_sdk_pod::encryption::auth_encryption::PodAeCiphertext;

#[cfg(not(target_os = "solana"))]
impl From<AeCiphertext> for PodAeCiphertext {
    fn from(decoded_ciphertext: AeCiphertext) -> Self {
        Self(decoded_ciphertext.to_bytes())
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<PodAeCiphertext> for AeCiphertext {
    type Error = AuthenticatedEncryptionError;

    fn try_from(pod_ciphertext: PodAeCiphertext) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod_ciphertext.0).ok_or(AuthenticatedEncryptionError::Deserialization)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::encryption::auth_encryption::AeKey, std::str::FromStr};

    #[test]
    fn ae_ciphertext_fromstr() {
        let ae_key = AeKey::new_rand();
        let expected_ae_ciphertext: PodAeCiphertext = ae_key.encrypt(0_u64).into();

        let ae_ciphertext_base64_str = format!("{}", expected_ae_ciphertext);
        let computed_ae_ciphertext = PodAeCiphertext::from_str(&ae_ciphertext_base64_str).unwrap();

        assert_eq!(expected_ae_ciphertext, computed_ae_ciphertext);
    }
}
