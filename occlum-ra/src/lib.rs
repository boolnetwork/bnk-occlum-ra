#![cfg_attr(not(feature = "std"), no_std)]
#![allow(dead_code)]
#![allow(clippy::unnecessary_cast)]
#![allow(unaligned_references)]
#![allow(clippy::char_lit_as_u8)]
#![allow(unused_imports)]
#![allow(clippy::or_fun_call)]

pub mod attestation;
pub mod dcap;
pub mod epid_occlum;
#[cfg(feature = "std")]
pub mod ias;
#[cfg(feature = "std")]
pub mod occlum_dcap;
#[cfg(feature = "std")]
pub mod tls;
pub mod verify;

use attestation::{DcapAttestation, EnclaveFields};
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};
pub use verify::{verify, verify_only_report};

#[cfg(feature = "std")]
extern crate occlum_dcap as occlum;
#[cfg(feature = "std")]
use occlum::sgx_report_data_t;

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;
#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
extern crate core;

/// return (key_der,cert_der)
#[cfg(feature = "std")]
pub fn generate_cert_key() -> Result<(Vec<u8>, Vec<u8>), String> {
    tls::generate_cert("".to_string())
}

/// verify cert_der
#[cfg(feature = "std")]
pub fn verify_cert(cert: &[u8]) -> Result<EnclaveFields, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    verify(cert, now)
}

/// create dcap report with additional info
#[cfg(feature = "std")]
pub fn create_dcap_report(additional_info: Vec<u8>) -> Result<Vec<u8>, String> {
    let report = match DcapAttestation::create_report(&additional_info) {
        Ok(r) => r,
        Err(_) => return Err("create_report fail".to_string()),
    };
    Ok(report.into_payload())
}

/// verify dcap report with additional info and return (mr_enclave.m,report_data.d)
#[cfg(feature = "std")]
pub fn verify_dcap_report(report: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    verify_only_report(&report, now)
}

#[cfg(feature = "std")]
pub fn get_fingerprint(key_policy: u16) -> Vec<u8> {
    let report_str = "GET KEY";
    let mut dcap_sgx = occlum_dcap::Dcap::new(report_str.as_bytes().to_vec());
    println!("Generate quote with report data : {:?}", report_str);
    dcap_sgx.dcap_quote_gen().unwrap();
    let report = dcap_sgx.dcap_quote_get_report_body().unwrap();

    occlum::get_key(report, key_policy).to_vec()
}

#[cfg(feature = "std")]
pub fn get_fingerprint_epid() -> Vec<u8> {
    let mut epid = occlum::EpidQuote::new();
    let group_id = epid.get_group_id();
    let target_info = epid.get_target_info();
    let report_data = sgx_report_data_t::default();
    //report_data.d = [7u8; 64];
    let epid_report = epid.get_epid_report(&target_info, &report_data);

    occlum::get_key(&epid_report.body).to_vec()
}

#[cfg(feature = "std")]
pub fn generate_epid() -> Result<(), String> {
    println!("start epid");
    let mut epid = occlum::EpidQuote::new();
    let group_id = epid.get_group_id();
    let target_info = epid.get_target_info();

    println!(
        "epid group_id{:?} target_info.mr.m{:?}",
        group_id, target_info.mr_enclave.m
    );

    let report_data = sgx_report_data_t::default();
    //report_data.d = [7u8; 64];
    let epid_report = epid.get_epid_report(&target_info, &report_data);
    println!("epid epid_report.cpu.svn{:?}", epid_report.body.cpu_svn.svn);

    Ok(())
}
