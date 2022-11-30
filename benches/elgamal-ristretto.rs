#[macro_use]
extern crate criterion;
use criterion::Criterion;

use elgamal_ristretto::private::SecretKey;
use elgamal_ristretto::public::PublicKey;
use rand_core::OsRng;

fn encrypt_ciphertext_additive(c: &mut Criterion) {
    let label = format!("Single Additive ElGamal Encryption");
    c.bench_function(&label, move |b| {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        b.iter(|| {
            pk.encrypt_additive(100);
        })
    });
}

fn decrypt_ciphertext_additive(c: &mut Criterion) {
    let label = format!("Single Additive ElGamal Decryption");
    c.bench_function(&label, move |b| {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ctxt = pk.encrypt_additive(100);

        b.iter(|| {
            sk.decrypt_additive(&ctxt, 1000000);
        })
    });
}

fn encrypt_ciphertext_add_plaintext(c: &mut Criterion) {
    let label = format!("Single Additive ElGamal Plaintext Addition");
    c.bench_function(&label, move |b| {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ctxt1 = pk.encrypt_additive(100);

        b.iter(|| ctxt1.add_by_plaintext(200))
    });
}

fn encrypt_ciphertext_add_ciphertext(c: &mut Criterion) {
    let label = format!("Single Additive ElGamal Ciphertext Addition");
    c.bench_function(&label, move |b| {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ctxt1 = pk.encrypt_additive(100);
        let ctxt2 = pk.encrypt_additive(200);

        b.iter(|| ctxt1 + ctxt2)
    });
}

criterion_group!(
    benches,
    encrypt_ciphertext_additive,
    decrypt_ciphertext_additive,
    encrypt_ciphertext_add_plaintext,
    encrypt_ciphertext_add_ciphertext,
);
criterion_main!(benches);
