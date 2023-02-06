extern crate core;
pub mod tls;
pub mod verify;
pub mod dcap;
pub mod attestation;
pub mod occlum_dcap;

pub use tls::generate_cert;
pub use verify::{verify, verify_only_report};
use attestation::{EnclaveFields, DcapAttestation};

pub fn generate_cert_key() -> Result<(Vec<u8>,Vec<u8>),String>{
    println!("start generate_cert_key");
    generate_cert("".to_string())
}

pub fn verify_cert(cert:&[u8], now: u64) -> Result<EnclaveFields, String>{
    verify(cert,now)
}

pub fn create_dcap_report(additional_info:Vec<u8>) -> Vec<u8>{
    let report = DcapAttestation::create_report(&additional_info).unwrap();
    report.into_payload()
}

pub fn verify_dcap_report(report: Vec<u8>, now: u64)  -> Result<EnclaveFields, String>{
    verify_only_report(&report, now)
}