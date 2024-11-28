#[derive(Debug)]
pub enum VerificationError {
    InvalidSignature,
    InvaildFlags,
    InvalidPrivateKey,
    CorruptedSignature,
}
