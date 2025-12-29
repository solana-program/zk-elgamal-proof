use {
    crate::encryption::{
        elgamal::{ElGamalPubkey, ElGamalSecretKey},
        pedersen::PedersenOpening,
    },
    js_sys::Uint8Array,
    solana_zk_sdk::encryption::{grouped_elgamal, DECRYPT_HANDLE_LEN, PEDERSEN_COMMITMENT_LEN},
    wasm_bindgen::prelude::*,
};

const GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES_LEN: usize =
    DECRYPT_HANDLE_LEN * 2 + PEDERSEN_COMMITMENT_LEN;
const GROUPED_ELGAMAL_CIPHERTEXT_3_HANDLES_LEN: usize =
    DECRYPT_HANDLE_LEN * 3 + PEDERSEN_COMMITMENT_LEN;

#[wasm_bindgen]
pub struct GroupedElGamalCiphertext2Handles {
    pub(crate) inner: grouped_elgamal::GroupedElGamalCiphertext<2>,
}

crate::conversion::impl_inner_conversion!(
    GroupedElGamalCiphertext2Handles,
    grouped_elgamal::GroupedElGamalCiphertext<2>
);

#[wasm_bindgen]
impl GroupedElGamalCiphertext2Handles {
    /// Encrypts a 64-bit amount under two ElGamal public keys.
    #[wasm_bindgen(js_name = "encrypt")]
    pub fn encrypt(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        amount: u64,
    ) -> Self {
        let inner = grouped_elgamal::GroupedElGamal::encrypt(
            [&first_pubkey.inner, &second_pubkey.inner],
            amount,
        );
        Self { inner }
    }

    /// Encrypts a 64-bit amount under two ElGamal public keys using a specific opening.
    #[wasm_bindgen(js_name = "encryptWith")]
    pub fn encrypt_with(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        amount: u64,
        opening: &PedersenOpening,
    ) -> Self {
        let inner = grouped_elgamal::GroupedElGamal::encrypt_with(
            [&first_pubkey.inner, &second_pubkey.inner],
            amount,
            &opening.inner,
        );
        Self { inner }
    }

    /// Decrypts the ciphertext using a secret key and a handle index.
    /// Returns the decrypted amount as a u64, or `undefined` if decryption fails.
    #[wasm_bindgen(js_name = "decrypt")]
    pub fn decrypt(&self, secret_key: &ElGamalSecretKey, index: usize) -> Result<u64, JsValue> {
        match self.inner.decrypt_u32(&secret_key.inner, index) {
            Ok(Some(amount)) => Ok(amount),
            Ok(None) => Err(JsValue::from_str(
                "Decryption failed: The secret key may be incorrect or the encrypted amount may be out of range.",
            )),
            Err(e) => Err(JsValue::from_str(&format!("Decryption failed: {}", e))),
        }
    }

    /// Deserializes a 2-handle grouped ElGamal ciphertext from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<GroupedElGamalCiphertext2Handles, JsValue> {
        let expected_length = GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES_LEN;
        if bytes.length() as usize != expected_length {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for GroupedElGamalCiphertext2Handles: expected {}, got {}",
                expected_length,
                bytes.length()
            )));
        }

        let mut arr = vec![0u8; bytes.length() as usize];
        bytes.copy_to(&mut arr);

        grouped_elgamal::GroupedElGamalCiphertext::<2>::from_bytes(&arr)
            .map(|inner| Self { inner })
            .ok_or_else(|| JsValue::from_str("Invalid bytes for GroupedElGamalCiphertext2Handles"))
    }

    /// Serializes the 2-handle grouped ElGamal ciphertext to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

#[wasm_bindgen]
pub struct GroupedElGamalCiphertext3Handles {
    pub(crate) inner: grouped_elgamal::GroupedElGamalCiphertext<3>,
}

crate::conversion::impl_inner_conversion!(
    GroupedElGamalCiphertext3Handles,
    grouped_elgamal::GroupedElGamalCiphertext<3>
);

#[wasm_bindgen]
impl GroupedElGamalCiphertext3Handles {
    /// Encrypts a 64-bit amount under three ElGamal public keys.
    #[wasm_bindgen(js_name = "encrypt")]
    pub fn encrypt(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        third_pubkey: &ElGamalPubkey,
        amount: u64,
    ) -> Self {
        let inner = grouped_elgamal::GroupedElGamal::encrypt(
            [
                &first_pubkey.inner,
                &second_pubkey.inner,
                &third_pubkey.inner,
            ],
            amount,
        );
        Self { inner }
    }

    /// Encrypts a 64-bit amount under three ElGamal public keys using a specific opening.
    #[wasm_bindgen(js_name = "encryptWith")]
    pub fn encrypt_with(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        third_pubkey: &ElGamalPubkey,
        amount: u64,
        opening: &PedersenOpening,
    ) -> Self {
        let inner = grouped_elgamal::GroupedElGamal::encrypt_with(
            [
                &first_pubkey.inner,
                &second_pubkey.inner,
                &third_pubkey.inner,
            ],
            amount,
            &opening.inner,
        );
        Self { inner }
    }

    /// Decrypts the ciphertext using a secret key and a handle index.
    /// Returns the decrypted amount as a u64, or `undefined` if decryption fails.
    #[wasm_bindgen(js_name = "decrypt")]
    pub fn decrypt(&self, secret_key: &ElGamalSecretKey, index: usize) -> Result<u64, JsValue> {
        match self.inner.decrypt_u32(&secret_key.inner, index) {
            Ok(Some(amount)) => Ok(amount),
            Ok(None) => Err(JsValue::from_str(
                "Decryption failed: The secret key may be incorrect or the encrypted amount may be out of range.",
            )),
            Err(e) => Err(JsValue::from_str(&format!("Decryption failed: {}", e))),
        }
    }

    /// Deserializes a 3-handle grouped ElGamal ciphertext from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<GroupedElGamalCiphertext3Handles, JsValue> {
        let expected_length = GROUPED_ELGAMAL_CIPHERTEXT_3_HANDLES_LEN;
        if bytes.length() as usize != expected_length {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for GroupedElGamalCiphertext3Handles: expected {}, got {}",
                expected_length,
                bytes.length()
            )));
        }

        let mut arr = vec![0u8; bytes.length() as usize];
        bytes.copy_to(&mut arr);

        grouped_elgamal::GroupedElGamalCiphertext::<3>::from_bytes(&arr)
            .map(|inner| Self { inner })
            .ok_or_else(|| JsValue::from_str("Invalid bytes for GroupedElGamalCiphertext3Handles"))
    }

    /// Serializes the 3-handle grouped ElGamal ciphertext to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::encryption::elgamal::ElGamalKeypair, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_grouped_elgamal_2_handles_cycle() {
        let keypair1 = ElGamalKeypair::new_rand();
        let keypair2 = ElGamalKeypair::new_rand();
        let amount: u64 = 123456789;

        let ciphertext = GroupedElGamalCiphertext2Handles::encrypt(
            &keypair1.pubkey(),
            &keypair2.pubkey(),
            amount,
        );

        // Decrypt with first key
        let decrypted1 = ciphertext.decrypt(&keypair1.secret(), 0);
        assert_eq!(decrypted1, Ok(amount));

        // Decrypt with second key
        let decrypted2 = ciphertext.decrypt(&keypair2.secret(), 1);
        assert_eq!(decrypted2, Ok(amount));

        // Decrypt with wrong key fails
        let keypair_wrong = ElGamalKeypair::new_rand();
        let decrypted_wrong = ciphertext.decrypt(&keypair_wrong.secret(), 0);
        assert!(decrypted_wrong.is_err());

        // Decrypt with wrong index fails
        let decrypted_wrong_index = ciphertext.decrypt(&keypair1.secret(), 1);
        assert!(decrypted_wrong_index.is_err());
    }

    #[wasm_bindgen_test]
    fn test_grouped_elgamal_3_handles_cycle() {
        let keypair1 = ElGamalKeypair::new_rand();
        let keypair2 = ElGamalKeypair::new_rand();
        let keypair3 = ElGamalKeypair::new_rand();
        let amount: u64 = 987654321;

        let ciphertext = GroupedElGamalCiphertext3Handles::encrypt(
            &keypair1.pubkey(),
            &keypair2.pubkey(),
            &keypair3.pubkey(),
            amount,
        );

        // Decrypt with each key
        assert_eq!(ciphertext.decrypt(&keypair1.secret(), 0), Ok(amount));
        assert_eq!(ciphertext.decrypt(&keypair2.secret(), 1), Ok(amount));
        assert_eq!(ciphertext.decrypt(&keypair3.secret(), 2), Ok(amount));

        // Decrypt with wrong key fails
        let keypair_wrong = ElGamalKeypair::new_rand();
        assert!(ciphertext.decrypt(&keypair_wrong.secret(), 1).is_err());
    }

    #[wasm_bindgen_test]
    fn test_bytes_roundtrip_2_handles() {
        let keypair1 = ElGamalKeypair::new_rand();
        let keypair2 = ElGamalKeypair::new_rand();
        let amount: u64 = 55;

        let ciphertext = GroupedElGamalCiphertext2Handles::encrypt(
            &keypair1.pubkey(),
            &keypair2.pubkey(),
            amount,
        );

        let bytes = ciphertext.to_bytes();
        // N=2 -> (2+1)*32 = 96 bytes
        assert_eq!(bytes.len(), 96);
        let recovered =
            GroupedElGamalCiphertext2Handles::from_bytes(&Uint8Array::from(bytes.as_slice()))
                .unwrap();

        assert_eq!(recovered.decrypt(&keypair1.secret(), 0), Ok(amount));
        assert_eq!(recovered.decrypt(&keypair2.secret(), 1), Ok(amount));
    }

    #[wasm_bindgen_test]
    fn test_bytes_roundtrip_3_handles() {
        let keypair1 = ElGamalKeypair::new_rand();
        let keypair2 = ElGamalKeypair::new_rand();
        let keypair3 = ElGamalKeypair::new_rand();
        let amount: u64 = 77;

        let ciphertext = GroupedElGamalCiphertext3Handles::encrypt(
            &keypair1.pubkey(),
            &keypair2.pubkey(),
            &keypair3.pubkey(),
            amount,
        );

        let bytes = ciphertext.to_bytes();
        // N=3 -> (3+1)*32 = 128 bytes
        assert_eq!(bytes.len(), 128);
        let recovered =
            GroupedElGamalCiphertext3Handles::from_bytes(&Uint8Array::from(bytes.as_slice()))
                .unwrap();

        assert_eq!(recovered.decrypt(&keypair1.secret(), 0), Ok(amount));
        assert_eq!(recovered.decrypt(&keypair2.secret(), 1), Ok(amount));
        assert_eq!(recovered.decrypt(&keypair3.secret(), 2), Ok(amount));
    }
}
