use bitflags::bitflags;

//TODO: figure out what the actual type is in the kernel crate
type ObjectId = u32;

pub struct Cap {
    target: ObjectId,
    accessor: ObjectId,
    permissions: ,
    //TODO: work on these later
    //gates: Gates
    //revocation: Revoc
    siglen: u16,    // in paper said type Length, just using u16
    sig: Box<[u8]>, // variable length sig
}

pub struct Permissions(u8); // pretty sure we can make this smaller right

#[rustfmt::skip] // so the bits are all nice and neat
bitflags! {
    impl Permissions: u8 {
        const Read =     0b00000001;
        const Write =    0b00000010;
        const Execute =  0b00000100;
        const Use =      0b00001000;

    }
}

pub enum CapErr {
    InvalidSignature,
}

impl Cap {
    // if the signature is a part of itself, then there should really be a new capability function,
    // actually now that im rereading a paper, looks like a capability must be created and then
    // must be signed with a different object, maybe the Sig should be an Option type then?
    pub fn new(target: ObjectId, accessor: ObjectId) -> Self {
        todo!();
    }

    pub fn verify_sig(&self) -> Result<(), CapErr> {
        todo!();
    }
}
