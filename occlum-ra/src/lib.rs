extern crate core;
pub mod attestation;
pub mod dcap;
pub mod occlum_dcap;
pub mod tls;
pub mod verify;

use attestation::{DcapAttestation, EnclaveFields};
use std::time::{SystemTime, UNIX_EPOCH};
pub use tls::generate_cert;
pub use verify::{verify, verify_only_report};

use sgx_types::sgx_key_128bit_t;
extern crate occlum_dcap as occlum;

/// return (key_der,cert_der)
pub fn generate_cert_key() -> Result<(Vec<u8>, Vec<u8>), String> {
    println!("start generate_cert_key");
    generate_cert("".to_string())
}

/// verify cert_der
pub fn verify_cert(cert: &[u8]) -> Result<EnclaveFields, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    verify(cert, now)
}

/// create dcap report with additional info
pub fn create_dcap_report(additional_info: Vec<u8>) -> Result<Vec<u8>, String> {
    let report = match DcapAttestation::create_report(&additional_info) {
        Ok(r) => r,
        Err(_) => return Err("create_report fail".to_string()),
    };
    Ok(report.into_payload())
}

/// verify dcap report with additional info and return (mr_enclave.m,report_data.d)
pub fn verify_dcap_report(report: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    verify_only_report(&report, now)
}


pub fn get_fingerprint() -> sgx_key_128bit_t{
    let report_str = "GET KEY";
    let mut dcap_demo = occlum_dcap::DcapDemo::new(report_str.as_bytes().to_vec());
    println!("Generate quote with report data : {:?}", report_str);
    dcap_demo.dcap_quote_gen().unwrap();
    let report = dcap_demo.dcap_quote_get_report_body().unwrap();

    occlum::get_key(report)
}