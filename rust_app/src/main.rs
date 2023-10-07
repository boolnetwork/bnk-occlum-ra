// use occlum_ra;

// use occlum_ra::{generate_cert_key, generate_epid, get_fingerprint, get_fingerprint_epid, verify_cert};
use std::time::{SystemTime, UNIX_EPOCH};
use gmp::mpz::Mpz;
use paillier::{BigInt, KeyGeneration, Paillier};
// use occlum_ra::attestation::{AttestationReport, AttestationStyle, IasAttestation};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
use zk_paillier::zkproofs::BlumModulesProof;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() {
    env_logger::init();

    println!("start");
    let (ek, dk) = Paillier::keypair_safe_primes().keys();
    println!("======start======");
    assert_eq!(&dk.p % 4, BigInt::from(3));
    assert_eq!(&dk.q % 4, BigInt::from(3));
    let proof = BlumModulesProof::prove(ek.n.clone(), dk.p.clone(), dk.q.clone()).unwrap();
    assert!(proof.verify(ek.n));

    println!("test_mod_floor pass");
}
