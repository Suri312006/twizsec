use twizsec::{Permissions, SecCtx, SigningScheme, VerifyingKey};

use crate::Object;

pub struct MMU {}

impl MMU {
    // i know this isnt exactly how its supposed to work but its
    // really hard to emulate everything that happens physically
    // so im trying to break it down into logical steps
    pub fn access_obj(
        obj: Object,
        curr_ctx: SecCtx,
        // this priv key would be coming from the kernel
        obj_priv_key: [u8; 32],
    ) -> Result<(), std::io::Error> {
        if let Some(caps) = curr_ctx.find_caps(obj.id) {
            // we have all the caps, all that matters is that one of them is valid?
            // how are we checking for these capabilities
            // are we going to look for the most permissive capability?
            // what about revoc?
            for cap in caps {
                // according to the talks ive had with daniel, these verifying keys are cached inside the kernel
                let v_key = VerifyingKey::new(SigningScheme::Ecdsa, &obj_priv_key).unwrap();
                cap.verify_sig(v_key)
                    .map_err(|_| std::io::ErrorKind::PermissionDenied)?
            }
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Your sec ctx doesnt have the necessary perms",
            ));
        }

        Ok(())
    }
}
