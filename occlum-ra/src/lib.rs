extern crate core;
pub mod attestation;
pub mod dcap;
#[cfg(not(feature = "no_std"))]
pub mod occlum_dcap;
#[cfg(not(feature = "no_std"))]
pub mod ias;
#[cfg(not(feature = "no_std"))]
pub mod epid_occlum;
#[cfg(not(feature = "no_std"))]
pub mod tls;
pub mod verify;

use attestation::{DcapAttestation, EnclaveFields};
use std::time::{SystemTime, UNIX_EPOCH};
pub use verify::{verify, verify_only_report};

#[cfg(not(feature = "no_std"))]
extern crate occlum_dcap as occlum;
#[cfg(not(feature = "no_std"))]
use occlum::sgx_report_data_t;

/// return (key_der,cert_der)
#[cfg(not(feature = "no_std"))]
pub fn generate_cert_key() -> Result<(Vec<u8>, Vec<u8>), String> {
    println!("start generate_cert_key");
    tls::generate_cert("".to_string())
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
#[cfg(not(feature = "no_std"))]
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

#[cfg(not(feature = "no_std"))]
pub fn get_fingerprint() -> Vec<u8> {
    let report_str = "GET KEY";
    let mut dcap_sgx = occlum_dcap::Dcap::new(report_str.as_bytes().to_vec());
    println!("Generate quote with report data : {:?}", report_str);
    dcap_sgx.dcap_quote_gen().unwrap();
    let report = dcap_sgx.dcap_quote_get_report_body().unwrap();

    occlum::get_key(report).to_vec()
}

#[cfg(not(feature = "no_std"))]
pub fn generate_epid() -> Result<(), String> {
    println!("start epid");
    let mut epid = occlum::EpidQuote::new();
    let group_id = epid.get_group_id();
    let mut target_info = epid.get_target_info();

    println!(
        "epid group_id{:?} target_info.mr.m{:?}",
        group_id, target_info.mr_enclave.m
    );

    let mut report_data = sgx_report_data_t::default();
    report_data.d = [7u8; 64];
    let epid_report = epid.get_epid_report(&mut target_info, &mut report_data);
    println!("epid epid_report.cpu.svn{:?}", epid_report.body.cpu_svn.svn);

    Ok(())
}
