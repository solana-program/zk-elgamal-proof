use {
    crate::encryption::elgamal::{WasmElGamalPubkey, WasmElGamalSecretKey},
    js_sys::Uint8Array,
    solana_zk_sdk::encryption::{
        grouped_elgamal::{GroupedElGamal, GroupedElGamalCiphertext},
        DECRYPT_HANDLE_LEN, PEDERSEN_COMMITMENT_LEN,
    },
    wasm_bindgen::prelude::*,
};

const GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES_LEN: usize =
    DECRYPT_HANDLE_LEN * 2 + PEDERSEN_COMMITMENT_LEN;
const GROUPED_ELGAMAL_CIPHERTEXT_3_HANDLES_LEN: usize =
    DECRYPT_HANDLE_LEN * 3 + PEDERSEN_COMMITMENT_LEN;

#[wasm_bindgen(js_name = "GroupedElGamalCiphertext2Handles")]
pub struct WasmGroupedElGamalCiphertext2Handles {
    pub(crate) inner: GroupedElGamalCiphertext<2>,
}

crate::conversion::impl_inner_conversion!(
    WasmGroupedElGamalCiphertext2Handles,
    GroupedElGamalCiphertext<2>
);

#[wasm_bindgen]
impl WasmGroupedElGamalCiphertext2Handles {
    /// Encrypts a 64-bit amount under two ElGamal public keys.
    #[wasm_bindgen(js_name = "encrypt")]
    pub fn encrypt(
        first_pubkey: &WasmElGamalPubkey,
        second_pubkey: &WasmElGamalPubkey,
        amount: u64,
    ) -> Self {
        let inner = GroupedElGamal::encrypt([&first_pubkey.inner, &second_pubkey.inner], amount);
        Self { inner }
    }

    /// Decrypts the ciphertext using a secret key and a handle index.
    /// Returns the decrypted amount as a u64, or `undefined` if decryption fails.
    #[wasm_bindgen(js_name = "decrypt")]
    pub fn decrypt(&self, secret_key: &WasmElGamalSecretKey, index: usize) -> Option<u64> {
        // The `decrypt_u32` function returns a `Result<Option<u64>>`. Flatten the result
        // to return `undefined` on error or if no amount is found.
        self.inner
            .decrypt_u32(&secret_key.inner, index)
            .ok()
            .flatten()
    }

    /// Deserializes a 2-handle grouped ElGamal ciphertext from a byte slice.
    /// Returns `undefined` if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<WasmGroupedElGamalCiphertext2Handles, JsValue> {
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

        GroupedElGamalCiphertext::<2>::from_bytes(&arr)
            .map(|inner| Self { inner })
            .ok_or_else(|| JsValue::from_str("Invalid bytes for GroupedElGamalCiphertext2Handles"))
    }

    /// Serializes the 2-handle grouped ElGamal ciphertext to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

#[wasm_bindgen(js_name = "GroupedElGamalCiphertext3Handles")]
pub struct WasmGroupedElGamalCiphertext3Handles {
    pub(crate) inner: GroupedElGamalCiphertext<3>,
}

crate::conversion::impl_inner_conversion!(
    WasmGroupedElGamalCiphertext3Handles,
    GroupedElGamalCiphertext<3>
);

#[wasm_bindgen]
impl WasmGroupedElGamalCiphertext3Handles {
    /// Encrypts a 64-bit amount under three ElGamal public keys.
    #[wasm_bindgen(js_name = "encrypt")]
    pub fn encrypt(
        first_pubkey: &WasmElGamalPubkey,
        second_pubkey: &WasmElGamalPubkey,
        third_pubkey: &WasmElGamalPubkey,
        amount: u64,
    ) -> Self {
        let inner = GroupedElGamal::encrypt(
            [
                &first_pubkey.inner,
                &second_pubkey.inner,
                &third_pubkey.inner,
            ],
            amount,
        );
        Self { inner }
    }

    /// Decrypts the ciphertext using a secret key and a handle index.
    /// Returns the decrypted amount as a u64, or `undefined` if decryption fails.
    #[wasm_bindgen(js_name = "decrypt")]
    pub fn decrypt(&self, secret_key: &WasmElGamalSecretKey, index: usize) -> Option<u64> {
        self.inner
            .decrypt_u32(&secret_key.inner, index)
            .ok()
            .flatten()
    }

    /// Deserializes a 3-handle grouped ElGamal ciphertext from a byte slice.
    /// Returns `undefined` if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &Uint8Array) -> Result<WasmGroupedElGamalCiphertext3Handles, JsValue> {
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

        GroupedElGamalCiphertext::<3>::from_bytes(&arr)
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
    use {super::*, crate::encryption::elgamal::WasmElGamalKeypair, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_grouped_elgamal_2_handles_cycle() {
        let keypair1 = WasmElGamalKeypair::new_rand();
        let keypair2 = WasmElGamalKeypair::new_rand();
        let amount: u64 = 123456789;

        let ciphertext = WasmGroupedElGamalCiphertext2Handles::encrypt(
            &keypair1.pubkey(),
            &keypair2.pubkey(),
            amount,
        );

        // Decrypt with first key
        let decrypted1 = ciphertext.decrypt(&keypair1.secret(), 0);
        assert_eq!(decrypted1, Some(amount));

        // Decrypt with second key
        let decrypted2 = ciphertext.decrypt(&keypair2.secret(), 1);
        assert_eq!(decrypted2, Some(amount));

        // Decrypt with wrong key fails
        let keypair_wrong = WasmElGamalKeypair::new_rand();
        let decrypted_wrong = ciphertext.decrypt(&keypair_wrong.secret(), 0);
        assert!(decrypted_wrong.is_none());

        // Decrypt with wrong index fails
        let decrypted_wrong_index = ciphertext.decrypt(&keypair1.secret(), 1);
        assert!(decrypted_wrong_index.is_none());
    }

    #[wasm_bindgen_test]
    fn test_grouped_elgamal_3_handles_cycle() {
        let keypair1 = WasmElGamalKeypair::new_rand();
        let keypair2 = WasmElGamalKeypair::new_rand();
        let keypair3 = WasmElGamalKeypair::new_rand();
        let amount: u64 = 987654321;

        let ciphertext = WasmGroupedElGamalCiphertext3Handles::encrypt(
            &keypair1.pubkey(),
            &keypair2.pubkey(),
            &keypair3.pubkey(),
            amount,
        );

        // Decrypt with each key
        assert_eq!(ciphertext.decrypt(&keypair1.secret(), 0), Some(amount));
        assert_eq!(ciphertext.decrypt(&keypair2.secret(), 1), Some(amount));
        assert_eq!(ciphertext.decrypt(&keypair3.secret(), 2), Some(amount));

        // Decrypt with wrong key fails
        let keypair_wrong = WasmElGamalKeypair::new_rand();
        assert!(ciphertext.decrypt(&keypair_wrong.secret(), 1).is_none());
    }

    #[wasm_bindgen_test]
    fn test_bytes_roundtrip_2_handles() {
        let keypair1 = WasmElGamalKeypair::new_rand();
        let keypair2 = WasmElGamalKeypair::new_rand();
        let amount: u64 = 55;

        let ciphertext = WasmGroupedElGamalCiphertext2Handles::encrypt(
            &keypair1.pubkey(),
            &keypair2.pubkey(),
            amount,
        );

        let bytes = ciphertext.to_bytes();
        // N=2 -> (2+1)*32 = 96 bytes
        assert_eq!(bytes.len(), 96);
        let recovered =
            WasmGroupedElGamalCiphertext2Handles::from_bytes(&Uint8Array::from(bytes.as_slice()))
                .unwrap();

        assert_eq!(recovered.decrypt(&keypair1.secret(), 0), Some(amount));
        assert_eq!(recovered.decrypt(&keypair2.secret(), 1), Some(amount));
    }

    #[wasm_bindgen_test]
    fn test_bytes_roundtrip_3_handles() {
        let keypair1 = WasmElGamalKeypair::new_rand();
        let keypair2 = WasmElGamalKeypair::new_rand();
        let keypair3 = WasmElGamalKeypair::new_rand();
        let amount: u64 = 77;

        let ciphertext = WasmGroupedElGamalCiphertext3Handles::encrypt(
            &keypair1.pubkey(),
            &keypair2.pubkey(),
            &keypair3.pubkey(),
            amount,
        );

        let bytes = ciphertext.to_bytes();
        // N=3 -> (3+1)*32 = 128 bytes
        assert_eq!(bytes.len(), 128);
        let recovered =
            WasmGroupedElGamalCiphertext3Handles::from_bytes(&Uint8Array::from(bytes.as_slice()))
                .unwrap();

        assert_eq!(recovered.decrypt(&keypair1.secret(), 0), Some(amount));
        assert_eq!(recovered.decrypt(&keypair2.secret(), 1), Some(amount));
        assert_eq!(recovered.decrypt(&keypair3.secret(), 2), Some(amount));
    }
}
