use {
    js_sys::Uint8Array,
    solana_seed_derivable::SeedDerivable,
    solana_signature::Signature,
    solana_zk_sdk::encryption::auth_encryption,
    solana_zk_sdk_pod::encryption::{AE_CIPHERTEXT_LEN, AE_KEY_LEN},
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

/// Byte length of an ed25519 signature.
const SIGNATURE_LEN: usize = 64;

#[wasm_bindgen]
pub struct AeKey {
    pub(crate) inner: auth_encryption::AeKey,
}

crate::conversion::impl_inner_conversion!(AeKey, auth_encryption::AeKey);

#[wasm_bindgen]
impl AeKey {
    /// Creates a new, random authenticated encryption key.
    #[wasm_bindgen(constructor)]
    pub fn new_rand() -> Self {
        Self {
            inner: auth_encryption::AeKey::new_rand(),
        }
    }

    /// Returns the message that a Solana signer must sign in order to
    /// deterministically derive an `AeKey` via `fromSignature`.
    ///
    /// The message is `b"AeKey" || public_seed`. For the spl-token-2022
    /// confidential extension, the `public_seed` is the 32-byte token
    /// account address.
    #[wasm_bindgen(js_name = "signerMessage")]
    pub fn signer_message(public_seed: Uint8Array) -> Vec<u8> {
        let mut seed = vec![0u8; public_seed.length() as usize];
        public_seed.copy_to(&mut seed);
        [b"AeKey".as_ref(), seed.as_ref()].concat()
    }

    /// Derives an `AeKey` from a 64-byte ed25519 signature over the
    /// message returned by `signerMessage`.
    #[wasm_bindgen(js_name = "fromSignature")]
    pub fn from_signature(signature: Uint8Array) -> Result<AeKey, JsValue> {
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
        auth_encryption::AeKey::new_from_signature(&signature)
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deterministically derives an `AeKey` from a seed.
    ///
    /// The seed must be between 16 and 65535 bytes in length.
    #[wasm_bindgen(js_name = "fromSeed")]
    pub fn from_seed(seed: Uint8Array) -> Result<AeKey, JsValue> {
        let mut bytes = vec![0u8; seed.length() as usize];
        seed.copy_to(&mut bytes);
        <auth_encryption::AeKey as SeedDerivable>::from_seed(&bytes)
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deterministically derives an `AeKey` from a BIP39 mnemonic seed
    /// phrase and optional passphrase.
    #[wasm_bindgen(js_name = "fromSeedPhraseAndPassphrase")]
    pub fn from_seed_phrase_and_passphrase(
        seed_phrase: &str,
        passphrase: &str,
    ) -> Result<AeKey, JsValue> {
        <auth_encryption::AeKey as SeedDerivable>::from_seed_phrase_and_passphrase(
            seed_phrase,
            passphrase,
        )
        .map(|inner| Self { inner })
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserializes an `AeKey` from a byte slice.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(uint8_array: Uint8Array) -> Result<AeKey, JsValue> {
        if uint8_array.length() as usize != AE_KEY_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for AeKey: expected {}, got {}",
                AE_KEY_LEN,
                uint8_array.length()
            )));
        }

        let mut bytes = [0u8; AE_KEY_LEN];
        uint8_array.copy_to(&mut bytes);

        auth_encryption::AeKey::try_from(bytes.as_ref())
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Serializes the `AeKey` to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Clone is needed here because the zk-sdk implements only `From<AeKey>` for
        // `[u8; AE_KEY_LEN]` and not `From<&AeKey>`.
        // TODO: Consider implementing `From<&AeKey>` for `[u8; AE_KEY_LEN]`.
        let bytes: [u8; AE_KEY_LEN] = self.inner.clone().into();
        bytes.to_vec()
    }

    /// Encrypts a 64-bit amount.
    #[wasm_bindgen]
    pub fn encrypt(&self, amount: u64) -> AeCiphertext {
        self.inner.encrypt(amount).into()
    }

    /// Decrypts a ciphertext. Returns the amount if successful, otherwise `undefined`.
    #[wasm_bindgen]
    pub fn decrypt(&self, ciphertext: &AeCiphertext) -> Result<u64, JsValue> {
        self.inner.decrypt(&ciphertext.inner).ok_or_else(|| {
            JsValue::from_str(
                "Decryption failed: The ciphertext may be tampered or the key incorrect.",
            )
        })
    }
}

#[wasm_bindgen]
pub struct AeCiphertext {
    pub(crate) inner: auth_encryption::AeCiphertext,
}

crate::conversion::impl_inner_conversion!(AeCiphertext, auth_encryption::AeCiphertext);

#[wasm_bindgen]
impl AeCiphertext {
    /// Deserializes an `AeCiphertext` from a byte slice.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(uint8_array: Uint8Array) -> Option<AeCiphertext> {
        if uint8_array.length() as usize != AE_CIPHERTEXT_LEN {
            return None;
        }

        let mut bytes = [0u8; AE_CIPHERTEXT_LEN];
        uint8_array.copy_to(&mut bytes);

        auth_encryption::AeCiphertext::from_bytes(&bytes).map(|inner| Self { inner })
    }

    /// Serializes the `AeCiphertext` to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Decrypts the ciphertext. Returns the amount if successful, otherwise `undefined`.
    #[wasm_bindgen]
    pub fn decrypt(&self, key: &AeKey) -> Option<u64> {
        self.inner.decrypt(key)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_ae_key_roundtrip() {
        let key = AeKey::new_rand();
        let key_bytes = key.to_bytes();
        assert_eq!(key_bytes.len(), 16);
        let recovered_key = AeKey::from_bytes(Uint8Array::from(key_bytes.as_slice())).unwrap();
        assert_eq!(key.to_bytes(), recovered_key.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_bytes_with_invalid_key() {
        let short_bytes = vec![0; 15];
        assert!(AeKey::from_bytes(Uint8Array::from(short_bytes.as_slice())).is_err());
        let long_bytes = vec![0; 17];
        assert!(AeKey::from_bytes(Uint8Array::from(long_bytes.as_slice())).is_err());
    }

    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_cycle() {
        let key = AeKey::new_rand();
        let amount: u64 = 987654321;

        let ciphertext = key.encrypt(amount);
        let decrypted_amount_from_key = key.decrypt(&ciphertext);
        assert_eq!(decrypted_amount_from_key, Ok(amount));

        let decrypted_amount_from_ciphertext = ciphertext.decrypt(&key);
        assert_eq!(decrypted_amount_from_ciphertext, Some(amount));
    }

    #[wasm_bindgen_test]
    fn test_ciphertext_is_not_deterministic() {
        let key = AeKey::new_rand();
        let amount: u64 = 555;

        let ciphertext1 = key.encrypt(amount);
        let ciphertext2 = key.encrypt(amount);

        // Due to the random nonce, two encryptions of the same amount should not be equal
        assert_ne!(ciphertext1.to_bytes(), ciphertext2.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_decryption_with_wrong_key_fails() {
        let key1 = AeKey::new_rand();
        let key2 = AeKey::new_rand(); // A different key
        let amount: u64 = 100;
        let ciphertext = key1.encrypt(amount);

        // Attempt to decrypt with wrong key
        let result = key2.decrypt(&ciphertext);
        assert!(!result.is_ok());
    }

    #[wasm_bindgen_test]
    fn test_signer_message_format() {
        let seed = [7u8; 32];
        let expected = [b"AeKey".as_ref(), seed.as_ref()].concat();
        let msg = AeKey::signer_message(Uint8Array::from(seed.as_ref()));
        assert_eq!(msg, expected);
    }

    #[wasm_bindgen_test]
    fn test_signer_message_domain_separated_from_elgamal() {
        // The AeKey and ElGamalSecretKey domain separators must differ so that
        // signing the same public seed for both keys yields different signatures.
        let seed = Uint8Array::from([0u8; 32].as_ref());
        let ae_msg = AeKey::signer_message(seed.clone());
        let elgamal_msg = crate::encryption::elgamal::ElGamalSecretKey::signer_message(seed);
        assert_ne!(ae_msg, elgamal_msg);
    }

    #[wasm_bindgen_test]
    fn test_from_signature_determinism() {
        let signature_bytes = [3u8; 64];
        let sig = Uint8Array::from(signature_bytes.as_ref());

        let key_a = AeKey::from_signature(sig.clone()).unwrap();
        let key_b = AeKey::from_signature(sig).unwrap();
        assert_eq!(key_a.to_bytes(), key_b.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_signature_rejects_wrong_length() {
        let short = vec![0u8; 63];
        assert!(AeKey::from_signature(Uint8Array::from(short.as_slice())).is_err());
        let long = vec![0u8; 65];
        assert!(AeKey::from_signature(Uint8Array::from(long.as_slice())).is_err());
    }

    #[wasm_bindgen_test]
    fn test_from_seed_roundtrip() {
        let seed = [9u8; 32];
        let seed_arr = Uint8Array::from(seed.as_ref());
        let key_a = AeKey::from_seed(seed_arr.clone()).unwrap();
        let key_b = AeKey::from_seed(seed_arr).unwrap();
        assert_eq!(key_a.to_bytes(), key_b.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_seed_rejects_short_seed() {
        // `AeKey::from_seed` requires at least 16 bytes of seed material.
        let too_short = vec![0u8; 8];
        assert!(AeKey::from_seed(Uint8Array::from(too_short.as_slice())).is_err());
    }

    #[wasm_bindgen_test]
    fn test_from_seed_phrase_roundtrip() {
        let phrase =
            "blanket tower apple sunset trigger muscle fame detect absent copper cram guard";
        let passphrase = "";

        let a = AeKey::from_seed_phrase_and_passphrase(phrase, passphrase).unwrap();
        let b = AeKey::from_seed_phrase_and_passphrase(phrase, passphrase).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());

        let different = AeKey::from_seed_phrase_and_passphrase(phrase, "pw").unwrap();
        assert_ne!(different.to_bytes(), a.to_bytes());
    }
}
