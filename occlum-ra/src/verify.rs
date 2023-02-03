use webpki::Error;
use crate::attestation::{AttestationReport, AttestationStyle, DcapAttestation, EnclaveFields};

pub fn verify(cert: &[u8], now: u64) -> Result<EnclaveFields, String> {
    // Before we reach here, Webpki already verifed the cert is properly signed
    let (payload, pub_k) = extract_data(cert)?;
    let report = match AttestationReport::from_payload(&payload) {
        Ok(r) => r,
        Err(e) => {
            println!("Compatible with older payload: {:?}", e);
            AttestationReport {
                style: AttestationStyle::EPID,
                data: payload,
            }
        }
    };

    let enclave = match DcapAttestation::verify(&report, now){
        Err(e) => return Err("DcapAttestation::verify err".to_string()),
        Ok(enclave) => enclave ,
    };

    if enclave.report_data != pub_k.to_vec() {
        return Err("Error::InvalidPublicKey".to_string());
    }
    Ok(enclave)
}

pub(crate) fn extract_data(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Search for Public Key prime256v1 OID
    let prime256v1_oid = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let mut offset = cert_der
        .windows(prime256v1_oid.len())
        .position(|window| window == prime256v1_oid)
        .ok_or("Error::InvalidSelfSignedCert".to_string())?;
    offset += 11; // 10 + TAG (0x03)

    // Obtain Public Key length
    let mut len = cert_der[offset] as usize;
    if len > 0x80 {
        len = (cert_der[offset + 1] as usize) * 0x100 + (cert_der[offset + 2] as usize);
        offset += 2;
    }

    // Obtain Public Key
    offset += 1;
    let pub_k = cert_der[offset + 2..offset + len].to_vec(); // skip "00 04"

    // Search for Netscape Comment OID
    let ns_cmt_oid = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x0D,
    ];
    let mut offset = cert_der
        .windows(ns_cmt_oid.len())
        .position(|window| window == ns_cmt_oid)
        .ok_or("Error::InvalidSelfSignedCert".to_string())?;
    offset += 12; // 11 + TAG (0x04)

    // Obtain Netscape Comment length
    let mut len = cert_der[offset] as usize;
    if len > 0x80 {
        len = (cert_der[offset + 1] as usize) * 0x100 + (cert_der[offset + 2] as usize);
        offset += 2;
    }

    // Obtain Netscape Comment
    offset += 1;
    let payload = cert_der[offset..offset + len].to_vec();

    Ok((payload, pub_k))
}