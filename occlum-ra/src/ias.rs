use log::{debug, error, info};
use sgx_types::*;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::prelude::v1::*;
use std::str;
use std::sync::Arc;
use sha2::Digest;
use webpki::DNSNameRef;
use http_req::{request::RequestBuilder, tls, uri::Uri};
use core::convert::TryFrom;
use http_req::request::Method::{GET, POST};
use serde::{Serialize, Deserialize};
use crate::epid_occlum::EpidReport;

pub const DEV_HOSTNAME: &'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX: &'static str = "/sgx/dev/attestation/v4/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/sgx/dev/attestation/v4/report";

#[derive(Serialize,Deserialize ,Debug)]
pub struct Data{
    isvEnclaveQuote: String
}

pub struct Net {
    pub spid: sgx_spid_t,
    pub ias_key: String,
}

// todo use http_req https://github.com/mesalock-linux/http_req-sgx/blob/5d0f7474c7/examples/request_builder_get.rs

impl Net {
    pub fn new(spid: String, ias_key: String) -> Self {
        let spid = Utils::decode_spid(&spid);
        Self { spid, ias_key }
    }

    pub fn get_sigrl(&self, fd: String, gid: u32) -> Result<Vec<u8>, String> {
        let resp = self.http_get_sigrl(fd.clone(), SIGRL_SUFFIX.to_string(), gid)?;
        return Ok(resp);
    }

    pub fn get_report(&self, fd: String, quote: Vec<u8>) -> Result<EpidReport, String> {
        let encoded_quote = base64::encode(&quote[..]);
        let (att_report, sig, sig_cert) = self.http_get_report(fd.clone(),REPORT_SUFFIX.to_string()
                                        ,encoded_quote).unwrap();

        return Ok(EpidReport {
            ra_report: att_report.as_bytes().to_vec(),
            signature: sig.as_bytes().to_vec(),
            cert_raw: sig_cert.as_bytes().to_vec(),
        });
    }

    fn http_get_sigrl(&self, ias_url: String, suffix: String, gid: u32) -> Result<Vec<u8>,String>{
        let url = format!("{ias_url}{suffix}{gid:08x}");
        println!("url {:?}",url);

        let addr: Uri = Uri::try_from(url.as_str())
            .or_else(|_| Err("Error::Uri bad".to_string()))?;

        let stream = TcpStream::connect((addr.host().unwrap(), addr.corr_port()))
            .or_else(|_| Err("Error::TcpStream connect fail".to_string()))?;

        let mut stream = tls::Config::default()
            .connect(addr.host().unwrap_or(""), stream)
            .or_else(|_| Err("Error::TLS connect fail".to_string()))?;

        let mut writer = Vec::new();

        let response = RequestBuilder::new(&addr)
            .method(GET)
            .header("Ocp-Apim-Subscription-Key",&self.ias_key)
            .header("Connection", "Close")
            .send(&mut stream, &mut writer)
            .or_else(|_| Err("Error::RequestBuilder send fail".to_string()))?;

        println!("Status: {} {}", response.status_code(), response.reason());

        let body_len = response.headers().get("Content-Length").unwrap();
        if body_len == "0"{
            return Ok(Vec::new());
        }
        return Ok(base64::decode(str::from_utf8(&writer).unwrap())
            .map_err(|_| "parse body failed".to_string())?);
    }

    fn http_get_report(&self, ias_url: String, suffix: String, encode_json: String) -> Result<(String, String, String), String>{
        let url = format!("{ias_url}{suffix}");
        println!("url {:?}",url);
        let data = Data{
            isvEnclaveQuote: encode_json
        };
        let encode_json = serde_json::to_string(&data).unwrap();
        println!("encode_json {:?}",encode_json);
        println!("len {}",encode_json.len());

        let addr: Uri = Uri::try_from(url.as_str())
            .or_else(|_| Err("Error::Uri bad".to_string()))?;

        let stream = TcpStream::connect((addr.host().unwrap(), addr.corr_port()))
            .or_else(|_| Err("Error::TcpStream connect fail".to_string()))?;

        let mut stream = tls::Config::default()
            .connect(addr.host().unwrap_or(""), stream)
            .or_else(|_| Err("Error::TLS connect fail".to_string()))?;

        let mut writer = Vec::new();

        let response = RequestBuilder::new(&addr)
            .method(POST)
            .header("Ocp-Apim-Subscription-Key",&self.ias_key)
            .header("Content-Type","application/json")
            .header("Content-Length",&encode_json.len())
            .header("Connection", "Close")
            .body(encode_json.as_bytes())
            .send(&mut stream, &mut writer)
            .or_else(|_| Err("Error::RequestBuilder send fail".to_string()))?;

        println!("Status: {} {}", response.status_code(), response.reason());
        println!("report response: {:?}",response);

        // parse the response
        let content_len = response.headers().get("Content-Length").unwrap();
        let body_len = content_len.parse::<u32>().map_err(|_| "parse len failed".to_string())?;
        let sig = response.headers().get("X-IASReport-Signature").unwrap().to_owned();
        let mut cert = response.headers().get("X-IASReport-Signing-Certificate").unwrap().to_owned();

        // Remove %0A from cert, and only obtain the signing cert
        cert = cert.replace("%0A", "");
        cert = Self::percent_decode(cert);
        let v: Vec<&str> = cert.split("-----").collect();
        println!("sig_cert amount: {:?}",v.len());
        let sig_cert = v[2].to_string();

        let mut attn_report = "".to_string();
        if body_len != 0 {
            attn_report = str::from_utf8(&writer).unwrap().to_string();
            println!("IasAttestation report: {}", attn_report);
        };

        return Ok((attn_report, sig, sig_cert));
    }

    fn parse_response_attn_report(resp: &[u8]) -> Result<(String, String, String), String> {
        info!("parse_response_attn_report");
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut respp = httparse::Response::new(&mut headers);
        let result = respp.parse(resp);
        debug!("parse result {:?}", result);

        let msg: &'static str;

        match respp.code {
            Some(200) => msg = "OK Operation Successful",
            Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
            Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
            Some(500) => msg = "Internal error occurred",
            Some(503) => {
                msg = "Service is currently not able to process the request (due to
                a temporary overloading or maintenance). This is a
                temporary state – the same request can be repeated after
                some time. "
            }
            _ => {
                println!("DBG:{}", respp.code.unwrap());
                msg = "Unknown error occured"
            }
        }

        debug!("{}", msg);
        let mut len_num: u32 = 0;

        let mut sig = String::new();
        let mut cert = String::new();
        let mut attn_report = String::new();

        for i in 0..respp.headers.len() {
            let h = respp.headers[i];
            //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
            match h.name {
                "Content-Length" => {
                    let len_str = String::from_utf8(h.value.to_vec())
                        .map_err(|_| "parse h.value failed".to_string())?;
                    len_num = len_str
                        .parse::<u32>()
                        .map_err(|_| "parse len failed".to_string())?;
                    println!("content length = {}", len_num);
                }
                "X-IASReport-Signature" => {
                    sig = str::from_utf8(h.value)
                        .map_err(|_| "parse h.value failed".to_string())?
                        .to_string()
                }
                "X-IASReport-Signing-Certificate" => {
                    cert = str::from_utf8(h.value)
                        .map_err(|_| "parse h.value failed".to_string())?
                        .to_string()
                }
                _ => (),
            }
        }

        // Remove %0A from cert, and only obtain the signing cert
        cert = cert.replace("%0A", "");
        cert = Self::percent_decode(cert);
        let v: Vec<&str> = cert.split("-----").collect();
        let sig_cert = v[2].to_string();

        if len_num != 0 {
            let header_len = result.unwrap().unwrap();
            let resp_body = &resp[header_len..];
            attn_report = str::from_utf8(resp_body).unwrap().to_string();
            println!("IasAttestation report: {}", attn_report);
        }

        // len_num == 0
        Ok((attn_report, sig, sig_cert))
    }

    fn make_ias_client_config() -> rustls::ClientConfig {
        let mut config = rustls::ClientConfig::new();

        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        config
    }

    fn percent_decode(orig: String) -> String {
        let v: Vec<&str> = orig.split("%").collect();
        let mut ret = String::new();
        ret.push_str(v[0]);
        if v.len() > 1 {
            for s in v[1..].iter() {
                ret.push(u8::from_str_radix(&s[0..2], 16).unwrap() as char);
                ret.push_str(&s[2..]);
            }
        }
        ret
    }

    fn parse_response_sigrl(resp: &[u8]) -> Result<Vec<u8>, String> {
        info!("parse_response_sigrl");
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut respp = httparse::Response::new(&mut headers);
        let result = respp.parse(resp);
        debug!("parse result {:?}", result);
        debug!("parse response{:?}", respp);

        let msg: &'static str;

        match respp.code {
            Some(200) => msg = "OK Operation Successful",
            Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
            Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
            Some(500) => msg = "Internal error occurred",
            Some(503) => {
                msg = "Service is currently not able to process the request (due to
                a temporary overloading or maintenance). This is a
                temporary state – the same request can be repeated after
                some time. "
            }
            _ => msg = "Unknown error occured",
        }

        debug!("{}", msg);
        let mut len_num: u32 = 0;

        for i in 0..respp.headers.len() {
            let h = respp.headers[i];
            if h.name == "content-length" {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str
                    .parse::<u32>()
                    .map_err(|_| "parse len failed".to_string())?;
                println!("content length = {}", len_num);
            }
        }

        if len_num != 0 {
            let header_len = result.unwrap().unwrap();
            let resp_body = &resp[header_len..];
            println!("Base64-encoded SigRL: {:?}", resp_body);

            return Ok(base64::decode(str::from_utf8(resp_body).unwrap())
                .map_err(|_| "parse body failed".to_string())?);
        }

        // len_num == 0
        Ok(Vec::new())
    }
}

pub struct Utils {}

impl Utils {
    fn decode_spid(hex: &str) -> sgx_spid_t {
        let mut spid = sgx_spid_t::default();
        let hex = hex.trim();

        if hex.len() < 16 * 2 {
            log::trace!("Input spid file len ({}) is incorrect!", hex.len());
            return spid;
        }

        let decoded_vec = Self::decode_hex(hex);

        spid.id.copy_from_slice(&decoded_vec[..16]);

        spid
    }

    pub fn decode_hex(hex: &str) -> Vec<u8> {
        let mut r: Vec<u8> = Vec::new();
        let mut chars = hex.chars().enumerate();
        loop {
            let (pos, first) = match chars.next() {
                None => break,
                Some(elt) => elt,
            };
            if first == ' ' {
                continue;
            }
            let (_, second) = match chars.next() {
                None => panic!("pos = {}d", pos),
                Some(elt) => elt,
            };
            r.push((Self::decode_hex_digit(first) << 4) | Self::decode_hex_digit(second));
        }
        r
    }

    fn decode_hex_digit(digit: char) -> u8 {
        match digit {
            '0'..='9' => digit as u8 - '0' as u8,
            'a'..='f' => digit as u8 - 'a' as u8 + 10,
            'A'..='F' => digit as u8 - 'A' as u8 + 10,
            _ => panic!(),
        }
    }
}