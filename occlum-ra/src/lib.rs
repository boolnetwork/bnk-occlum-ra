extern crate core;
pub mod tls;
pub mod verify;
pub mod dcap;
pub mod attestation;
pub mod occlum_dcap;

pub use tls::generate_cert;
pub use verify::{verify, verify_only_report};
use attestation::{EnclaveFields, DcapAttestation};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate_cert_key() -> Result<(Vec<u8>,Vec<u8>),String>{
    println!("start generate_cert_key");
    generate_cert("".to_string())
}

pub fn verify_cert(cert:&[u8]) -> Result<EnclaveFields, String>{
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    verify(cert,now)
}

pub fn create_dcap_report(additional_info:Vec<u8>) -> Result<Vec<u8>, String>{
    let report = match DcapAttestation::create_report(&additional_info) {
        Ok(r) => r,
        Err(_) => return Err("create_report fail".to_string()),
    };
    Ok(report.into_payload())
}

pub fn verify_dcap_report(report: Vec<u8>)  -> Result<(Vec<u8>, Vec<u8>), String>{
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    verify_only_report(&report, now)
}