use thiserror::Error;

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum ParseError {
    #[error("String is the wrong size")]
    WrongSize,
    #[error("Invalid Base64 string")]
    Invalid,
    #[error("Invalid argument or zero value provided")]
    InvalidArgument,
}
