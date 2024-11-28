use hex_literal::hex;
use twizsec::{ObjectId, Permissions, UnsignedCap};

#[test]
fn basic_creation_and_verification() {
    let accessor_id: ObjectId = 12345689;
    let target_id: ObjectId = 987654321;
    //https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.5
    let target_priv_key = hex!("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    // basically this priv_key needs to be 32 bytes long, if we want the keys to be more adaptable,
    // we would need a key struct and abstract it away, since right now the implementation only
    // works if we use a hard-coded size

    // now lets say accessor wants to reach target
    let target_rw_cap = UnsignedCap::new(
        target_id,
        accessor_id,
        Permissions::READ | Permissions::WRITE,
    );

    let target_rw_signed_cap = target_rw_cap.sign(target_priv_key);

    target_rw_signed_cap
        .verify_sig(target_priv_key)
        .expect("should be verified ");
}
