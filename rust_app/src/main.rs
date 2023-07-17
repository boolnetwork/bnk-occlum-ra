use occlum_ra;

use occlum_ra::{generate_cert_key, generate_epid, get_fingerprint, get_fingerprint_epid, verify_cert};
use std::time::{SystemTime, UNIX_EPOCH};
use gmp::mpz::Mpz;
use occlum_ra::attestation::{AttestationReport, AttestationStyle, IasAttestation};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() {
    env_logger::init();

    println!("start");
    let cert_der = match generate_cert_key() {
        Err(e) => panic!("error: {:?}", e),
        Ok((a, b)) => b,
    };
    let res = verify_cert(&cert_der);
    println!("verify_cert result {:?}", res);

    println!("GMP rust bindings test");
    let two: Mpz = From::<i64>::from(2);
    let eight: Mpz = From::<i64>::from(8);
    let minuseight: Mpz = From::<i64>::from(-8);
    let three: Mpz = From::<i64>::from(3);
    let minusthree: Mpz = From::<i64>::from(-3);
    assert_eq!(eight.div_floor(&three), two);
    assert_eq!(eight.div_floor(&minusthree), minusthree);
    assert_eq!(minuseight.div_floor(&three), minusthree);
    assert_eq!(minuseight.div_floor(&minusthree), two);
    println!("test_div_floor pass");
    let one: Mpz = From::<i64>::from(1);
    let minusone: Mpz = From::<i64>::from(-1);
    let two: Mpz = From::<i64>::from(2);
    let minustwo: Mpz = From::<i64>::from(-2);
    let three: Mpz = From::<i64>::from(3);
    let minusthree: Mpz = From::<i64>::from(-3);
    let eight: Mpz = From::<i64>::from(8);
    let minuseight: Mpz = From::<i64>::from(-8);
    assert_eq!(eight.mod_floor(&three), two);
    assert_eq!(eight.mod_floor(&minusthree), minusone);
    assert_eq!(minuseight.mod_floor(&three), one);
    assert_eq!(minuseight.mod_floor(&minusthree), minustwo);
    println!("test_mod_floor pass");
}
