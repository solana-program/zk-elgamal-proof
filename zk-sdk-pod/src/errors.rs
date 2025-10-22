use thiserror::Error;

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum PodParseError {
    #[error("String is the wrong size")]
    WrongSize,
    #[error("Invalid Base64 string")]
    Invalid,
    #[error("Grouped ciphertext index out of bounds")]
    GroupedCiphertextIndexOutOfBounds,
}
