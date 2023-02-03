extern crate core;
pub mod tls;
pub mod verify;
pub mod dcap;
pub mod attestation;
pub mod occlum_dcap;

pub use tls::generate_cert;
pub use verify::verify;
use attestation::EnclaveFields;

pub fn generate_cert_key() -> Result<(Vec<u8>,Vec<u8>),String>{
    println!("start generate_cert_key");
    generate_cert("".to_string())
}

pub fn verify_cert(cert:&[u8], now: u64) -> Result<EnclaveFields, String>{
    verify(cert,now)
}

