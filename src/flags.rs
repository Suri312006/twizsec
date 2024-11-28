use bitflags::bitflags;

pub struct CapFlags(u8); // pretty sure we can make this smaller right

#[rustfmt::skip] // so the bits are all nice and neat
bitflags! {
    impl CapFlags: u8 {
        //TODO: flags here indicate which algorithm was used for signature generation.
        const SHA256 =  0b00000001;
        const ECDSA =   0b00000010;
    }
}
