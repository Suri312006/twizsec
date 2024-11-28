pub struct Permissions(u8); // pretty sure we can make this smaller right
use bitflags::bitflags;

#[rustfmt::skip] // so the bits are all nice and neat
bitflags! {
    impl Permissions: u8 {
        const READ =     0b00000001;
        const WRITE =    0b00000010;
        const EXEC =     0b00000100;
        const USE =      0b00001000;
    }
}