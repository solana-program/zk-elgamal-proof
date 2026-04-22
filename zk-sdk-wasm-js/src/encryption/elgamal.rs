use {
    crate::encryption::pedersen::{PedersenCommitment, PedersenOpening},
    js_sys::Uint8Array,
    solana_seed_derivable::SeedDerivable,
    solana_signature::Signature,
    solana_zk_sdk::encryption::elgamal,
    solana_zk_sdk_pod::encryption::{
        DECRYPT_HANDLE_LEN, ELGAMAL_CIPHERTEXT_LEN, ELGAMAL_PUBKEY_LEN, ELGAMAL_SECRET_KEY_LEN,
    },
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

/// Byte length of an ed25519 signature.
const SIGNATURE_LEN: usize = 64;

#[wasm_bindgen]
pub struct ElGamalPubkey {
    pub(crate) inner: elgamal::ElGamalPubkey,
}

crate::conversion::impl_inner_conversion!(ElGamalPubkey, elgamal::ElGamalPubkey);

#[wasm_bindgen]
impl ElGamalPubkey {
    /// Creates an ElGamal public key from a secret key.
    #[wasm_bindgen(js_name = "fromSecretKey")]
    pub fn from_secret_key(secret_key: &ElGamalSecretKey) -> Self {
        Self {
            inner: elgamal::ElGamalPubkey::new(secret_key),
        }
    }

    /// Deserializes an ElGamal public key from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(uint8_array: Uint8Array) -> Result<ElGamalPubkey, JsValue> {
        if uint8_array.length() as usize != ELGAMAL_PUBKEY_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for ElGamalPubkey: expected {}, got {}",
                ELGAMAL_PUBKEY_LEN,
                uint8_array.length()
            )));
        }

        let mut bytes = [0u8; ELGAMAL_PUBKEY_LEN];
        uint8_array.copy_to(&mut bytes);

        elgamal::ElGamalPubkey::try_from(bytes.as_ref())
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Serializes the ElGamal public key to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes: [u8; 32] = self.inner.into();
        bytes.to_vec()
    }

    /// Encrypts a 64-bit amount using the public key.
    #[wasm_bindgen(js_name = "encryptU64")]
    pub fn encrypt_u64(&self, amount: u64) -> ElGamalCiphertext {
        self.inner.encrypt(amount).into()
    }

    /// Encrypts a 64-bit amount using the public key and a specific opening.
    #[wasm_bindgen(js_name = "encryptWith")]
    pub fn encrypt_with(&self, amount: u64, opening: &PedersenOpening) -> ElGamalCiphertext {
        self.inner.encrypt_with(amount, &opening.inner).into()
    }
}

#[wasm_bindgen]
pub struct ElGamalSecretKey {
    pub(crate) inner: elgamal::ElGamalSecretKey,
}

crate::conversion::impl_inner_conversion!(ElGamalSecretKey, elgamal::ElGamalSecretKey);

#[wasm_bindgen]
impl ElGamalSecretKey {
    /// Creates a new, random ElGamal secret key.
    #[wasm_bindgen(constructor)]
    pub fn new_rand() -> Self {
        Self {
            inner: elgamal::ElGamalSecretKey::new_rand(),
        }
    }

    /// Returns the message that a Solana signer must sign in order to
    /// deterministically derive an `ElGamalSecretKey` via `fromSignature`.
    ///
    /// The message is `b"ElGamalSecretKey" || public_seed`. For the
    /// spl-token-2022 confidential extension, the `public_seed` is the
    /// 32-byte token account address.
    #[wasm_bindgen(js_name = "signerMessage")]
    pub fn signer_message(public_seed: Uint8Array) -> Vec<u8> {
        let mut seed = vec![0u8; public_seed.length() as usize];
        public_seed.copy_to(&mut seed);
        [b"ElGamalSecretKey".as_ref(), seed.as_ref()].concat()
    }

    /// Derives an `ElGamalSecretKey` from a 64-byte ed25519 signature
    /// over the message returned by `signerMessage`.
    #[wasm_bindgen(js_name = "fromSignature")]
    pub fn from_signature(signature: Uint8Array) -> Result<ElGamalSecretKey, JsValue> {
        let mut bytes = [0u8; SIGNATURE_LEN];
        if signature.length() as usize != SIGNATURE_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid signature length: expected {}, got {}",
                SIGNATURE_LEN,
                signature.length()
            )));
        }
        signature.copy_to(&mut bytes);
        let signature = Signature::from(bytes);
        elgamal::ElGamalSecretKey::new_from_signature(&signature)
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deterministically derives an `ElGamalSecretKey` from a seed.
    ///
    /// The seed must be between 32 and 65535 bytes in length.
    #[wasm_bindgen(js_name = "fromSeed")]
    pub fn from_seed(seed: Uint8Array) -> Result<ElGamalSecretKey, JsValue> {
        let mut bytes = vec![0u8; seed.length() as usize];
        seed.copy_to(&mut bytes);
        <elgamal::ElGamalSecretKey as SeedDerivable>::from_seed(&bytes)
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deterministically derives an `ElGamalSecretKey` from a BIP39 mnemonic
    /// seed phrase and optional passphrase.
    #[wasm_bindgen(js_name = "fromSeedPhraseAndPassphrase")]
    pub fn from_seed_phrase_and_passphrase(
        seed_phrase: &str,
        passphrase: &str,
    ) -> Result<ElGamalSecretKey, JsValue> {
        <elgamal::ElGamalSecretKey as SeedDerivable>::from_seed_phrase_and_passphrase(
            seed_phrase,
            passphrase,
        )
        .map(|inner| Self { inner })
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes an ElGamal secret key from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(uint8_array: Uint8Array) -> Result<ElGamalSecretKey, JsValue> {
        if uint8_array.length() as usize != ELGAMAL_SECRET_KEY_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for ElGamalSecretKey: expected {}, got {}",
                ELGAMAL_SECRET_KEY_LEN,
                uint8_array.length()
            )));
        }

        let mut bytes = [0u8; ELGAMAL_SECRET_KEY_LEN];
        uint8_array.copy_to(&mut bytes);

        elgamal::ElGamalSecretKey::try_from(bytes.as_ref())
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Serializes the ElGamal secret key to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }

    /// Decrypts an ElGamal ciphertext.
    /// Returns the decrypted amount as a `u64`, or `undefined` if decryption fails.
    #[wasm_bindgen(js_name = "decrypt")]
    pub fn decrypt(&self, ciphertext: &ElGamalCiphertext) -> Result<u64, JsValue> {
        self.inner
            .decrypt_u32(&ciphertext.inner)
            .ok_or_else(|| {
                JsValue::from_str(
                    "Decryption failed: The secret key may be incorrect or the encrypted amount may be out of range.",
                )
            })
    }
}

#[wasm_bindgen]
pub struct ElGamalKeypair {
    pub(crate) inner: elgamal::ElGamalKeypair,
}

crate::conversion::impl_inner_conversion!(ElGamalKeypair, elgamal::ElGamalKeypair);

#[wasm_bindgen]
impl ElGamalKeypair {
    /// Creates a new, random ElGamal keypair.
    #[wasm_bindgen(constructor)]
    pub fn new_rand() -> Self {
        Self {
            inner: elgamal::ElGamalKeypair::new_rand(),
        }
    }

    /// Creates an ElGamal keypair from a secret key.
    #[wasm_bindgen(js_name = "fromSecretKey")]
    pub fn from_secret_key(secret_key: &ElGamalSecretKey) -> Self {
        Self {
            inner: elgamal::ElGamalKeypair::new(secret_key.inner.clone()),
        }
    }

    /// Returns the message that a Solana signer must sign in order to
    /// deterministically derive an `ElGamalKeypair` via `fromSignature`.
    ///
    /// Identical to `ElGamalSecretKey.signerMessage` — provided on `ElGamalKeypair`
    /// for ergonomic access.
    #[wasm_bindgen(js_name = "signerMessage")]
    pub fn signer_message(public_seed: Uint8Array) -> Vec<u8> {
        ElGamalSecretKey::signer_message(public_seed)
    }

    /// Derives an `ElGamalKeypair` from a 64-byte ed25519 signature
    /// over the message returned by `signerMessage`.
    #[wasm_bindgen(js_name = "fromSignature")]
    pub fn from_signature(signature: Uint8Array) -> Result<ElGamalKeypair, JsValue> {
        let secret = ElGamalSecretKey::from_signature(signature)?;
        Ok(Self::from_secret_key(&secret))
    }

    /// Deterministically derives an `ElGamalKeypair` from a seed.
    ///
    /// The seed must be between 32 and 65535 bytes in length.
    #[wasm_bindgen(js_name = "fromSeed")]
    pub fn from_seed(seed: Uint8Array) -> Result<ElGamalKeypair, JsValue> {
        let secret = ElGamalSecretKey::from_seed(seed)?;
        Ok(Self::from_secret_key(&secret))
    }

    /// Deterministically derives an `ElGamalKeypair` from a BIP39 mnemonic
    /// seed phrase and optional passphrase.
    #[wasm_bindgen(js_name = "fromSeedPhraseAndPassphrase")]
    pub fn from_seed_phrase_and_passphrase(
        seed_phrase: &str,
        passphrase: &str,
    ) -> Result<ElGamalKeypair, JsValue> {
        let secret = ElGamalSecretKey::from_seed_phrase_and_passphrase(seed_phrase, passphrase)?;
        Ok(Self::from_secret_key(&secret))
    }

    /// Returns the public key of the keypair.
    pub fn pubkey(&self) -> ElGamalPubkey {
        ElGamalPubkey {
            inner: *self.inner.pubkey(),
        }
    }

    /// Returns the secret key of the keypair.
    pub fn secret(&self) -> ElGamalSecretKey {
        ElGamalSecretKey {
            inner: self.inner.secret().clone(),
        }
    }
}

#[wasm_bindgen]
pub struct ElGamalCiphertext {
    pub(crate) inner: elgamal::ElGamalCiphertext,
}

crate::conversion::impl_inner_conversion!(ElGamalCiphertext, elgamal::ElGamalCiphertext);

#[wasm_bindgen]
impl ElGamalCiphertext {
    /// Deserializes an ElGamal ciphertext from a byte slice.
    /// Returns `undefined` if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(uint8_array: Uint8Array) -> Option<ElGamalCiphertext> {
        if uint8_array.length() as usize != ELGAMAL_CIPHERTEXT_LEN {
            return None;
        }

        let mut bytes = [0u8; ELGAMAL_CIPHERTEXT_LEN];
        uint8_array.copy_to(&mut bytes);

        elgamal::ElGamalCiphertext::from_bytes(&bytes).map(|inner| Self { inner })
    }

    /// Serializes the ElGamal ciphertext to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Returns the commitment component of the ciphertext.
    pub fn commitment(&self) -> PedersenCommitment {
        PedersenCommitment {
            inner: self.inner.commitment,
        }
    }

    /// Returns the decryption handle component of the ciphertext.
    pub fn handle(&self) -> DecryptHandle {
        DecryptHandle {
            inner: self.inner.handle,
        }
    }
}

#[wasm_bindgen]
pub struct DecryptHandle {
    pub(crate) inner: elgamal::DecryptHandle,
}

crate::conversion::impl_inner_conversion!(DecryptHandle, elgamal::DecryptHandle);

#[wasm_bindgen]
impl DecryptHandle {
    /// Deserializes a decryption handle from a byte slice.
    /// Returns `undefined` if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(uint8_array: Uint8Array) -> Option<DecryptHandle> {
        if uint8_array.length() as usize != DECRYPT_HANDLE_LEN {
            return None;
        }

        let mut bytes = [0u8; DECRYPT_HANDLE_LEN];
        uint8_array.copy_to(&mut bytes);

        elgamal::DecryptHandle::from_bytes(&bytes).map(|inner| Self { inner })
    }

    /// Serializes the decryption handle to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_elgamal_keypair_creation_and_accessors() {
        let secret = ElGamalSecretKey::new_rand();
        let keypair = ElGamalKeypair::from_secret_key(&secret);

        let pubkey = keypair.pubkey();
        let derived_pubkey = ElGamalPubkey::from_secret_key(&secret);

        assert_eq!(pubkey.to_bytes(), derived_pubkey.to_bytes());
        assert_eq!(secret.to_bytes(), keypair.secret().to_bytes());

        let rand_keypair = ElGamalKeypair::new_rand();
        assert_ne!(rand_keypair.secret().to_bytes(), secret.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_pubkey_and_secretkey_bytes_roundtrip() {
        let keypair = ElGamalKeypair::new_rand();
        let secret = keypair.secret();
        let pubkey = keypair.pubkey();

        // Secret Key roundtrip
        let secret_bytes = secret.to_bytes();
        let recovered_secret =
            ElGamalSecretKey::from_bytes(Uint8Array::from(secret_bytes.as_slice())).unwrap();
        assert_eq!(secret.to_bytes(), recovered_secret.to_bytes());

        // Public Key roundtrip
        let pubkey_bytes = pubkey.to_bytes();
        let recovered_pubkey =
            ElGamalPubkey::from_bytes(Uint8Array::from(pubkey_bytes.as_slice())).unwrap();
        assert_eq!(pubkey.to_bytes(), recovered_pubkey.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_cycle() {
        let amount_to_encrypt: u64 = 55;
        let keypair = ElGamalKeypair::new_rand();
        let pubkey = keypair.pubkey();
        let secret_key = keypair.secret();

        let ciphertext = pubkey.encrypt_u64(amount_to_encrypt);
        let decrypted_amount = secret_key.decrypt(&ciphertext);
        assert_eq!(decrypted_amount, Ok(amount_to_encrypt));
    }

    #[wasm_bindgen_test]
    fn test_ciphertext_and_handle_bytes_roundtrip() {
        let keypair = ElGamalKeypair::new_rand();
        let ciphertext = keypair.pubkey().encrypt_u64(123);

        // Ciphertext roundtrip
        let ciphertext_bytes = ciphertext.to_bytes();
        let recovered_ciphertext =
            ElGamalCiphertext::from_bytes(Uint8Array::from(ciphertext_bytes.as_slice())).unwrap();
        assert_eq!(ciphertext.to_bytes(), recovered_ciphertext.to_bytes());

        // Handle roundtrip
        let handle = ciphertext.handle();
        let handle_bytes = handle.to_bytes();
        let recovered_handle =
            DecryptHandle::from_bytes(Uint8Array::from(handle_bytes.as_slice())).unwrap();
        assert_eq!(handle.to_bytes(), recovered_handle.to_bytes());

        // Commitment roundtrip
        let commitment = ciphertext.commitment();
        let commitment_bytes = commitment.to_bytes();
        let recovered_commitment = crate::encryption::pedersen::PedersenCommitment::from_bytes(
            Uint8Array::from(commitment_bytes.as_slice()),
        )
        .unwrap();
        assert_eq!(commitment.to_bytes(), recovered_commitment.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_decryption_with_wrong_key_fails() {
        let amount: u64 = 100;

        let keypair1 = ElGamalKeypair::new_rand();
        let keypair2 = ElGamalKeypair::new_rand(); // A different keypair

        let ciphertext = keypair1.pubkey().encrypt_u64(amount);
        let decrypted_result = keypair2.secret().decrypt(&ciphertext);
        assert!(decrypted_result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_elgamal_encryption_is_not_deterministic() {
        let keypair = ElGamalKeypair::new_rand();
        let pubkey = keypair.pubkey();
        let amount: u64 = 77;

        let ciphertext1 = pubkey.encrypt_u64(amount);
        let ciphertext2 = pubkey.encrypt_u64(amount);

        // Two encryptions of the same amount should not be equal due to random openings
        assert_ne!(ciphertext1.to_bytes(), ciphertext2.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_bytes_with_invalid_input() {
        let short_pubkey = vec![0; 31];
        assert!(ElGamalPubkey::from_bytes(Uint8Array::from(short_pubkey.as_slice())).is_err());
        let long_pubkey = vec![0; 33];
        assert!(ElGamalPubkey::from_bytes(Uint8Array::from(long_pubkey.as_slice())).is_err());
        let invalid_pubkey = vec![0xFF; 32];
        assert!(ElGamalPubkey::from_bytes(Uint8Array::from(invalid_pubkey.as_slice())).is_err());

        let short_secret = vec![0; 31];
        assert!(ElGamalSecretKey::from_bytes(Uint8Array::from(short_secret.as_slice())).is_err());
        let long_secret = vec![0; 33];
        assert!(ElGamalSecretKey::from_bytes(Uint8Array::from(long_secret.as_slice())).is_err());

        let short_ciphertext = vec![0; 63];
        assert!(
            ElGamalCiphertext::from_bytes(Uint8Array::from(short_ciphertext.as_slice())).is_none()
        );
        let long_ciphertext = vec![0; 65];
        assert!(
            ElGamalCiphertext::from_bytes(Uint8Array::from(long_ciphertext.as_slice())).is_none()
        );
        let invalid_ciphertext = vec![0xFF; 64];
        assert!(
            ElGamalCiphertext::from_bytes(Uint8Array::from(invalid_ciphertext.as_slice()))
                .is_none()
        );

        let short_handle = vec![0; 31];
        assert!(DecryptHandle::from_bytes(Uint8Array::from(short_handle.as_slice())).is_none());
        let long_handle = vec![0; 33];
        assert!(DecryptHandle::from_bytes(Uint8Array::from(long_handle.as_slice())).is_none());
        let invalid_handle = vec![0xFF; 32];
        assert!(DecryptHandle::from_bytes(Uint8Array::from(invalid_handle.as_slice())).is_none());
    }

    #[wasm_bindgen_test]
    fn test_elgamal_encrypt_with_correctness() {
        let keypair = ElGamalKeypair::new_rand();
        let amount: u64 = 42;
        let opening = PedersenOpening::new_rand();

        let ciphertext = keypair.pubkey().encrypt_with(amount, &opening);
        let decrypted = keypair.secret().decrypt(&ciphertext);
        assert_eq!(decrypted, Ok(amount));
    }

    #[wasm_bindgen_test]
    fn test_signer_message_format() {
        let seed = [7u8; 32];
        let expected = [b"ElGamalSecretKey".as_ref(), seed.as_ref()].concat();

        let from_secret = ElGamalSecretKey::signer_message(Uint8Array::from(seed.as_ref()));
        assert_eq!(from_secret, expected);

        let from_keypair = ElGamalKeypair::signer_message(Uint8Array::from(seed.as_ref()));
        assert_eq!(from_keypair, expected);
    }

    #[wasm_bindgen_test]
    fn test_from_signature_determinism() {
        let signature_bytes = [1u8; 64];
        let sig = Uint8Array::from(signature_bytes.as_ref());

        let secret_a = ElGamalSecretKey::from_signature(sig.clone()).unwrap();
        let secret_b = ElGamalSecretKey::from_signature(sig.clone()).unwrap();
        assert_eq!(secret_a.to_bytes(), secret_b.to_bytes());

        // Keypair derivation must yield the same secret as the secret-key path.
        let keypair = ElGamalKeypair::from_signature(sig).unwrap();
        assert_eq!(keypair.secret().to_bytes(), secret_a.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_signature_rejects_wrong_length() {
        let short = vec![0u8; 63];
        assert!(ElGamalSecretKey::from_signature(Uint8Array::from(short.as_slice())).is_err());
        let long = vec![0u8; 65];
        assert!(ElGamalKeypair::from_signature(Uint8Array::from(long.as_slice())).is_err());
    }

    #[wasm_bindgen_test]
    fn test_from_seed_roundtrip() {
        let seed = [9u8; 32];
        let seed_arr = Uint8Array::from(seed.as_ref());

        let secret_a = ElGamalSecretKey::from_seed(seed_arr.clone()).unwrap();
        let secret_b = ElGamalSecretKey::from_seed(seed_arr.clone()).unwrap();
        assert_eq!(secret_a.to_bytes(), secret_b.to_bytes());

        let keypair = ElGamalKeypair::from_seed(seed_arr).unwrap();
        assert_eq!(keypair.secret().to_bytes(), secret_a.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_seed_rejects_short_seed() {
        // `ElGamalSecretKey::from_seed` requires at least 32 bytes of seed material.
        let too_short = vec![0u8; 16];
        assert!(ElGamalSecretKey::from_seed(Uint8Array::from(too_short.as_slice())).is_err());
        assert!(ElGamalKeypair::from_seed(Uint8Array::from(too_short.as_slice())).is_err());
    }

    #[wasm_bindgen_test]
    fn test_from_seed_phrase_roundtrip() {
        let phrase =
            "blanket tower apple sunset trigger muscle fame detect absent copper cram guard";
        let passphrase = "";

        let a = ElGamalSecretKey::from_seed_phrase_and_passphrase(phrase, passphrase).unwrap();
        let b = ElGamalSecretKey::from_seed_phrase_and_passphrase(phrase, passphrase).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());

        let different = ElGamalSecretKey::from_seed_phrase_and_passphrase(phrase, "pw").unwrap();
        assert_ne!(different.to_bytes(), a.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_different_public_seeds_produce_different_keys() {
        // Domain separation across token accounts: different public seeds must
        // yield different signer messages, and therefore different keys for any
        // given (hypothetical) signer.
        let seed_a = Uint8Array::from([1u8; 32].as_ref());
        let seed_b = Uint8Array::from([2u8; 32].as_ref());

        let msg_a = ElGamalSecretKey::signer_message(seed_a);
        let msg_b = ElGamalSecretKey::signer_message(seed_b);
        assert_ne!(msg_a, msg_b);
    }
}
