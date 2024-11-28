use p256::ecdsa::{
    signature::{SignerMut, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

use crate::{
    flags::{CapFlags, HashingAlgo, SigningScheme},
    Permissions, VerificationError,
};

pub type ObjectId = u128;

pub struct Cap {
    pub target: ObjectId, // needs to be public for kernel access, could also do the java way of
    // getters and setters but not fully sure what the code style of the repo should be
    pub accessor: ObjectId, // needs to be public for kernel access

    permissions: Permissions,
    flags: CapFlags,

    //WARN: adding these fields means you need to update how the contents are being hashed below
    //gates: Gates
    //revocation: Revoc
    ///NOTE: AS BYTES
    siglen: u16,
    sig: [u8; 1024], // since we dont have a allocator, just using a "big enough" array to
                     // store the sig
}

pub struct UnsignedCap {
    pub target: ObjectId,
    pub accessor: ObjectId,
    permissions: Permissions,
    //WARN: adding these fields means you need to update how the contents are being hashed below
    //gates: Gates
    //revocation: Revoc
}

impl UnsignedCap {
    pub fn new(target: ObjectId, accessor: ObjectId, perms: Permissions) -> Self {
        Self {
            target,
            accessor,
            permissions: perms,
        }
    }

    /* How a signature is formed (according to the sec paper)
     * hashing all fields (including siglen, excluding sig)
     * apply digital hashing algorithm to the hash
     * bits in flags are set to identify which hashing algorithms were used
     */
    // the signing key is supposed to be the private key of the target object
    // capabilities are supposed to be immutable, makes no sense for this to take in a mutable
    // capability, makes more sense for it to consume the previous one to return a cap one?
    pub fn sign(self, target_priv_key: [u8; 32]) -> Cap {
        // first use the sha2 algorithm to hash the capability contents
        // then use ECDSA to form a signature.

        let flags = CapFlags::SHA256 | CapFlags::ECDSA; // set flags
        let siglen = (target_priv_key.len() * 2) as u16; // according to how ecdsa signatures work,
                                                         // multiplying by 8 because len() returns bytes not bits

        //NOTE: the total "hashable" content size is 288 bits => [u8;36] array! (for now atleast),
        let mut hash_arr: [u8; 36] = [0; 36];

        hash_arr[0..16].copy_from_slice(&self.accessor.to_le_bytes());
        hash_arr[16..32].copy_from_slice(&self.target.to_le_bytes());
        hash_arr[32] = self.permissions.bits();
        hash_arr[33] = flags.bits();
        hash_arr[34..36].copy_from_slice(&siglen.to_le_bytes());

        let mut hasher = Sha256::new();
        hasher.update(hash_arr);
        let hash = hasher.finalize();

        // hash has been generated, time to do the signing
        let mut signing_key = SigningKey::from_slice(&target_priv_key)
            .expect("Failed to create Signing Key from Target Private Key");
        let signature: Signature = signing_key.sign(hash.as_slice());

        let mut sig_buf: [u8; 1024] = [0; 1024];

        // this line can panic if somehow siglen is > 1024
        sig_buf[0..siglen as usize].copy_from_slice(signature.to_bytes().as_slice());

        Cap {
            accessor: self.accessor,
            target: self.target,
            permissions: self.permissions,
            flags,
            siglen,
            sig: sig_buf,
        }
    }
}

impl Cap {
    pub fn verify_sig(&self, target_priv_key: [u8; 32]) -> Result<(), VerificationError> {
        let signing_key = SigningKey::from_slice(&target_priv_key)
            .expect("Failed to create Signing Key from Target Private Key");
        let verifying_key = VerifyingKey::from(&signing_key);

        let mut hashing_algo = None;
        let mut signing_scheme = None;

        for flag in self.flags.iter() {
            match flag {
                CapFlags::ECDSA => {
                    if signing_scheme.is_some() {
                        return Err(VerificationError::InvaildFlags);
                    }
                    signing_scheme = Some(SigningScheme::Ecdsa)
                }
                CapFlags::SHA256 => {
                    if hashing_algo.is_some() {
                        return Err(VerificationError::InvaildFlags);
                    }
                    hashing_algo = Some(HashingAlgo::Sha256)
                }
                _ => {} // not a fan of this but have to otherwise it bugs you
            };
        }

        // sanity check
        if hashing_algo.is_none() || signing_scheme.is_none() {
            return Err(VerificationError::InvaildFlags);
        }

        let mut hash_arr: [u8; 36] = [0; 36];

        hash_arr[0..16].copy_from_slice(&self.accessor.to_le_bytes());
        hash_arr[16..32].copy_from_slice(&self.target.to_le_bytes());
        hash_arr[32] = self.permissions.bits();
        hash_arr[33] = self.flags.bits();
        hash_arr[34..36].copy_from_slice(&self.siglen.to_le_bytes());

        let hash = match hashing_algo.unwrap() {
            HashingAlgo::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(hash_arr);
                hasher.finalize()
            }
        };

        match signing_scheme.unwrap() {
            SigningScheme::Ecdsa => {
                let sig = Signature::from_slice(&self.sig[0..self.siglen as usize])
                    .expect("Reconstructing Signature Failed");

                verifying_key
                    .verify(hash.as_slice(), &sig)
                    //NOTE: does the kernel have logging capabilities to log this error?
                    .map_err(|_| VerificationError::InvalidSignature)
            }
        }
    }
}
