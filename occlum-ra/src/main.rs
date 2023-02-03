extern crate core;

use std::time::{SystemTime, UNIX_EPOCH};
use occlum_ra::{generate_cert_key, verify_cert};

pub mod tls;
pub mod verify;
pub mod dcap;
pub mod attestation;
pub mod occlum_dcap;

fn main() {
    println!("Hello, world!");

    let (key_der, cert_der) = generate_cert_key();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let res = verify_cert(cert_der, now);
    println!("test result {:?}",res);
}
