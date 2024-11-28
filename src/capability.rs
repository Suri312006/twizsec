use p256::ecdsa::{
    signature::{SignerMut, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

use crate::{flags::CapFlags, Permissions, VerificationError};
//TODO: figure out what the actual type is in the kernel crate
type ObjectId = u128;

pub struct Cap {
    pub target: ObjectId, // needs to be public for kernel access, could also do the java way of
    // getters and setters but not fully sure what the code style of the repo should be
    pub accessor: ObjectId, // needs to be public for kernel access

    permissions: Permissions,
    flags: CapFlags,

    //WARN: adding these fields means you have to change the hashing implementation in the
    //sign() function.
    //gates: Gates
    //revocation: Revoc
    ///NOTE: IN BITS
    siglen: u16,
    sig: [u8; 8192], // since we dont have a allocator, just using a "big enough" array to
                     // store the sig, this big value is the maximum value of a
                     // u16/8, made it this big since we want to support different algo's
                     // even those in the future
}

pub struct UnsignedCap {
    pub target: ObjectId, // needs to be public for kernel access, could also do the java way of
    // getters and setters but not fully sure what the code style of the repo should be
    pub accessor: ObjectId, // needs to be public for kernel access
    permissions: Permissions,
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
     *
     */
    // the signing key is supposed to be the private key of the target object
    // capabilities are supposed to be immutable, makes no sense for this to take in a mutable
    // capability, makes more sense for it to consume the previous one to return a cap one?
    pub fn sign(self, target_priv_key: &str) -> Cap {
        // first use the sha2 algorithm to hash the capability contents
        // then use ECDSA to form a signature.

        let flags = CapFlags::SHA256 | CapFlags::ECDSA; // set flags
        let siglen = (target_priv_key.len() * 8 * 2) as u16; // according to how ecdsa signatures work,
                                                             // multiplying by 8 because len() returns bytes not bits

        //NOTE: the total "hashable" content size is 96 bits => [u8;12] array! (for now atleast),
        let mut hash_arr: [u8; 12] = [0; 12];

        hash_arr[0..4].copy_from_slice(&self.accessor.to_le_bytes());
        hash_arr[4..8].copy_from_slice(&self.target.to_le_bytes());
        hash_arr[8] = self.permissions.bits();
        hash_arr[9] = flags.bits();
        hash_arr[10..12].copy_from_slice(&siglen.to_le_bytes());

        let mut hasher = Sha256::new();
        hasher.update(hash_arr);
        let hash = hasher.finalize();

        // hash has been generated, time to do the signing
        let mut signing_key = SigningKey::from_slice(target_priv_key.as_bytes())
            .expect("Failed to create Signing Key from Target Private Key");
        let signature: Signature = signing_key.sign(hash.as_slice());

        let mut sig_buf: [u8; 8192] = [0; 8192];

        // potentially unsafe, not sure if i shoud do bounds checks and panic?
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
    pub fn verify_sig(&self, target_priv_key: &str) -> Result<(), VerificationError> {
        let signing_key = SigningKey::from_slice(target_priv_key.as_bytes())
            .expect("Failed to create Signing Key from Target Private Key");
        let verifying_key = VerifyingKey::from(&signing_key);

        let mut hash_arr: [u8; 12] = [0; 12];

        hash_arr[0..4].copy_from_slice(&self.accessor.to_le_bytes());
        hash_arr[4..8].copy_from_slice(&self.target.to_le_bytes());
        hash_arr[8] = self.permissions.bits();
        hash_arr[9] = self.flags.bits();
        hash_arr[10..12].copy_from_slice(&self.siglen.to_le_bytes());

        let mut hasher = Sha256::new();
        hasher.update(hash_arr);
        let hash = hasher.finalize();

        let sig = Signature::from_slice(&self.sig[0..self.siglen as usize])
            .expect("Reconstructing Signature Failed");

        verifying_key
            .verify(hash.as_slice(), &sig)
            //NOTE: does the kernel have logging capabilities to log this error?
            .map_err(|_| VerificationError::InvalidSignature)
    }
}
