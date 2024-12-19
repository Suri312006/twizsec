use std::thread;

mod mmu;
use mmu::MMU;
use twizsec::{crypto::rand_32, Cap, ObjectId, Permissions, SecCtx};
/// shell of an object just for testing purposes
#[derive(Copy, Clone, Debug)]
pub struct Object {
    id: ObjectId,
    priv_key: [u8; 32],
}

impl Object {
    pub fn new(id: ObjectId, priv_key: [u8; 32]) -> Self {
        Object { id, priv_key }
    }
}

fn main() {
    // bootstrapping process
    let alice_priv_obj = Object::new(1, rand_32());
    let bob_priv_obj = Object::new(2, rand_32());

    // two processes
    let bob_proc = thread::spawn(move || {
        // bootstrapping
        let mut my_ctx = SecCtx::new(3);
        let priv_cap = Cap::new(
            bob_priv_obj.id,
            my_ctx.obj_id,
            Permissions::all(),
            bob_priv_obj.priv_key,
        )
        .unwrap();
        my_ctx.add_cap(priv_cap);
        // end bootstrap
        // assume that bob logs in with all this here

        // lets try to access our own object
        let data = MMU::access_obj(bob_priv_obj, my_ctx.clone(), bob_priv_obj.priv_key).unwrap();
        // let data = MMU::access_obj(alice_priv_obj, my_ctx, alice_priv_obj.priv_key).unwrap();
    });

    let alice_proc = thread::spawn(move || {
        // bootstrapping
        let mut my_ctx = SecCtx::new(4);
        let priv_cap = Cap::new(
            alice_priv_obj.id,
            my_ctx.obj_id,
            Permissions::all(),
            alice_priv_obj.priv_key,
        )
        .unwrap();
        my_ctx.add_cap(priv_cap);
        // end bootstrap
        // assume that alice logs in with all this here
        let data = MMU::access_obj(alice_priv_obj, my_ctx, alice_priv_obj.priv_key).unwrap();
    });

    bob_proc.join().unwrap();
    alice_proc.join().unwrap();

    // one has the permissions to access something
    // the other doesnt

    // what is the hypothetical scenario that we want to test?

    // lets assume there are a couple processes that are trying to access a few objects

    // and lets say that each of these objects has something inside them
    //
    // and these processes hold specific security contexts that allow them access to these objects
}
