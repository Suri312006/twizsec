#[derive(Debug)]
pub enum CapError {
    InvalidSignature,
    InvalidVerifyKey,
    InvalidFlags,
    CorruptedSignature,
}
