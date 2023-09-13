#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Request to QRNG failed: {0}")]
    RequestQrngError(String),
    #[error("The application does not support this algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("The application does not support this format: {0}")]
    InvalidFormat(String),
    #[error("This secret key length is not supported: {0}")]
    InvalidLengthSecretKey(usize),
    #[error("Invalid public key length: {0}")]
    InvalidLengthPublicKey(String),
    #[error("This secret key length is not supported: {0}")]
    InvalidLengthSignature(usize),
    #[error("Generate keys error: {0}")]
    GenerateKeys(String),
    #[error("Public key error: {0}")]
    PublicKeyError(String),
    #[error("Public key error: {0}")]
    SignError(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
