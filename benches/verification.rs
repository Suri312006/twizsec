//use criterion::{criterion_group, criterion_main, Criterion};
//
//fn criterion_benchmark(c: &mut Criterion) {
//    c.bench_function("verify", |b| b.iter(|| {}))
//}
//
//criterion_group!(benches, criterion_benchmark);
//criterion_main!(benches);
use criterion::{criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use std::hint::black_box;
use twizsec::{Cap, ObjectId, Permissions};

fn fibonacci(n: u64) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        n => fibonacci(n - 1) + fibonacci(n - 2),
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let accessor_id: ObjectId = 12345689;
    let target_id: ObjectId = 987654321;
    //https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.5
    let target_priv_key = hex!("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    // basically this priv_key needs to be 32 bytes long, if we want the keys to be more adaptable,
    // we would need a key struct and abstract it away, since right now the implementation only
    // works if we use a hard-coded size

    // now lets say accessor wants to reach target
    let target_rw_cap = Cap::new(
        target_id,
        accessor_id,
        Permissions::READ | Permissions::WRITE,
        target_priv_key,
    );

    c.bench_function("Verifying SHA256 and P256 ECDSA Signature", |b| {
        b.iter(|| target_rw_cap.verify_sig(black_box(target_priv_key)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
