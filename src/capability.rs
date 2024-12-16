use p256::ecdsa::{
    signature::{SignerMut, Verifier},
    Signature, SigningKey, VerifyingKey as p256VerifyingKey,
};
use sha2::{Digest, Sha256};

use crate::{
    flags::{CapFlags, HashingAlgo, SigningScheme},
    CapError, ObjectId, Permissions, VerifyingKey,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

impl Cap {
    pub fn new(
        target: ObjectId,
        accessor: ObjectId,
        perms: Permissions,
        target_priv_key: [u8; 32],
    ) -> Result<Self, CapError> {
        let flags = CapFlags::SHA256 | CapFlags::ECDSA; // set flags
        let siglen = 64_u16; // according to how p256 ecdsa signature work,

        let hash_arr = Cap::serialize(accessor, target, perms, flags, siglen);

        let mut hasher = Sha256::new();
        hasher.update(hash_arr);
        let hash = hasher.finalize();

        // hash has been generated, time to do the signing
        let mut signing_key =
            SigningKey::from_slice(&target_priv_key).map_err(|_| CapError::InvalidPrivateKey)?;

        let signature: Signature = signing_key.sign(hash.as_slice());

        let mut sig_buf: [u8; 1024] = [0; 1024];

        // this line can panic if somehow siglen is > 1024
        sig_buf[0..siglen as usize].copy_from_slice(signature.to_bytes().as_slice());

        Ok(Cap {
            accessor,
            target,
            permissions: perms,
            flags,
            siglen,
            sig: sig_buf,
        })
    }
    pub fn verify_sig(&self, verifying_key: VerifyingKey) -> Result<(), CapError> {
        let (hashing_algo, signing_scheme) = self.flags.parse()?;

        // i hate how unergonomic this is but i wanted to contain all the serialization to one
        // function and this is the best way i could think of
        let hash_arr = Cap::serialize(
            self.accessor,
            self.target,
            self.permissions,
            self.flags,
            self.siglen,
        );

        let hash = match hashing_algo {
            HashingAlgo::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(hash_arr);
                hasher.finalize()
            }
        };

        // sanity check
        if signing_scheme != verifying_key.scheme {
            return Err(CapError::InvalidVerifyKey);
        }

        match signing_scheme {
            SigningScheme::Ecdsa => {
                let vkey = p256VerifyingKey::from_sec1_bytes(verifying_key.as_bytes())
                    .map_err(|_| CapError::InvalidVerifyKey)?;
                let sig = Signature::from_slice(&self.sig[0..self.siglen as usize])
                    .map_err(|_| CapError::CorruptedSignature)?;

                vkey.verify(hash.as_slice(), &sig)
                    //NOTE: does the kernel have logging capabilities to log this error?
                    .map_err(|_| CapError::InvalidSignature)
            }
        }
    }

    /// returns all contents other than sig as a buffer ready to hash
    //NOTE: the total "hashable" content size is 288 bits => [u8;36] array! (for now atleast),
    fn serialize(
        accessor: ObjectId,
        target: ObjectId,
        perms: Permissions,
        flags: CapFlags,
        siglen: u16,
    ) -> [u8; 36] {
        let mut hash_arr: [u8; 36] = [0; 36];

        hash_arr[0..16].copy_from_slice(&accessor.to_le_bytes());
        hash_arr[16..32].copy_from_slice(&target.to_le_bytes());
        hash_arr[32] = perms.bits();
        hash_arr[33] = flags.bits();
        hash_arr[34..36].copy_from_slice(&siglen.to_le_bytes());

        hash_arr
    }
}
