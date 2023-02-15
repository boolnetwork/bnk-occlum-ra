const SEPARATOR: u8 = 0x7Cu8;

pub struct EpidReport {
    pub ra_report: Vec<u8>,
    pub signature: Vec<u8>,
    pub cert_raw: Vec<u8>,
}

impl EpidReport {
// use for transfer to payload of cert
pub fn into_payload(self) -> Vec<u8> {
    let separator: &[u8] = &[SEPARATOR];
    let mut payload = Vec::new();
    payload.extend(self.ra_report);
    payload.extend(separator);
    payload.extend(self.signature);
    payload.extend(separator);
    payload.extend(self.cert_raw);
    payload
}

pub fn from_payload(payload: &[u8]) -> Result<Self, String> {
    let mut iter = payload.split(|x| *x == SEPARATOR);
    let attn_report_raw = iter.next().ok_or("InvalidReportPayload".to_string())?;
    let sig_raw = iter.next().ok_or("InvalidReportPayload".to_string())?;
    let sig_cert_raw = iter.next().ok_or("InvalidReportPayload".to_string())?;
    Ok(Self {
        ra_report: attn_report_raw.to_vec(),
        signature: sig_raw.to_vec(),
        cert_raw: sig_cert_raw.to_vec(),
    })
}
}