use bitflags::bitflags;

use crate::CapError;

#[derive(PartialEq, Copy, Clone)]
pub struct CapFlags(u8); // pretty sure we can make this smaller right

#[rustfmt::skip] // so the bits are all nice and neat
bitflags! {
    impl CapFlags: u8 {
        //TODO: flags here indicate which algorithm was used for signature generation.
        const SHA256 =  0b00000001;
        const ECDSA =   0b00000010;
    }
}

// only for internal use to help with parsing, but why though? should we make this pub?
pub(crate) enum SigningScheme {
    Ecdsa,
}

// only for internal use
pub(crate) enum HashingAlgo {
    Sha256,
}

impl CapFlags {
    pub(crate) fn parse(&self) -> Result<(HashingAlgo, SigningScheme), CapError> {
        let mut hashing_algo = None;
        let mut signing_scheme = None;

        for flag in self.iter() {
            match flag {
                CapFlags::ECDSA => {
                    if signing_scheme.is_some() {
                        return Err(CapError::InvalidFlags);
                    }
                    signing_scheme = Some(SigningScheme::Ecdsa)
                }
                CapFlags::SHA256 => {
                    if hashing_algo.is_some() {
                        return Err(CapError::InvalidFlags);
                    }
                    hashing_algo = Some(HashingAlgo::Sha256)
                }
                _ => {} // not a fan of this but have to otherwise it bugs you
            };
        }

        // sanity check
        if hashing_algo.is_none() || signing_scheme.is_none() {
            return Err(CapError::InvalidFlags);
        }

        Ok((hashing_algo.unwrap(), signing_scheme.unwrap()))
    }
}
