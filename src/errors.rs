#[derive(Debug)]
pub enum CapError {
    InvalidSignature,
    InvalidPrivateKey,
    InvalidFlags,
    CorruptedSignature,
}
