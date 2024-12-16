use alloc::vec::{self, Vec};

use crate::{Cap, ObjectId};

pub struct SecCtx {
    // this is the object id for the ctx
    pub obj_id: ObjectId,
    // should this be a hashmap since a target object can have different capabilities?
    // does that even make sense
    caps: Vec<Cap>,
}

#[derive(Debug)]
pub enum SecCtxError {
    Internal,
}

impl SecCtx {
    pub fn new(obj_id: ObjectId) -> Self {
        SecCtx {
            obj_id,
            caps: Vec::new(),
        }
    }

    //lowkey how is this supposed to work, like when you actually want to add a
    //capability as a user
    pub fn add_cap(&mut self, cap: Cap) {
        self.caps.push(cap);
    }

    pub fn find_caps(&self, target_obj_id: ObjectId) -> Option<Vec<&Cap>> {
        let res: Vec<&Cap> = self
            .caps
            .iter()
            .filter(|e| e.target == target_obj_id)
            .collect();

        if res.len() == 0 {
            return None;
        }

        Some(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::{crypto::rand_32, Permissions};

    use super::*;
    #[test]
    fn iter_caps() {
        let mut sctx = SecCtx::new(1234);
        static NUM_CAPS: usize = 10;
        let mut cpy: [Option<Cap>; NUM_CAPS] = [None; NUM_CAPS];
        for i in 0..10 {
            let cap = Cap::new(128, 128, Permissions::READ, rand_32()).unwrap();
            sctx.add_cap(cap);
            cpy[i] = Some(cap);
        }

        let mut count = 0;
        for (i, cap) in sctx.find_caps(128).unwrap().into_iter().enumerate() {
            assert_eq!(cpy[i].unwrap(), *cap);
            count += 1;
        }
        assert_eq!(count, NUM_CAPS)
    }
}
