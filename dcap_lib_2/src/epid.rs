use std::ffi::CString;
use crate::prelude::*;
use rand::RngCore;

const SGXIOC_GET_EPID_GROUP_ID: u64 = 0x80047301;
const SGXIOC_GEN_EPID_QUOTE: u64 = 0xc0807302;
const SGXIOC_SELF_TARGET: u64 = 0x82007303;
const SGXIOC_CREATE_REPORT: u64 = 0xc0187304;
const SGXIOC_VERIFY_REPORT: u64 = 0x41b07305;

const SGXIOC_DETECT_DCAP_DRIVER: u64 = 0x80047306;
const SGXIOC_IS_EDMM_SUPPORTED: u64 = 0x80047300;

cfg_if::cfg_if! {
    if #[cfg(target_env = "musl")] {
        const IOCTL_GET_EPID_GROUP_ID: i32 = SGXIOC_GET_EPID_GROUP_ID as i32;
        const IOCTL_GEN_EPID_QUOTE: i32 = SGXIOC_GEN_EPID_QUOTE as i32;
        const IOCTL_SELF_TARGET: i32 = SGXIOC_SELF_TARGET as i32;
        const IOCTL_CREATE_REPORT: i32 = SGXIOC_CREATE_REPORT as i32;
        const IOCTL_VERIFY_REPORT: i32 = SGXIOC_VERIFY_REPORT as i32;

        const IOCTL_DETECT_DCAP_DRIVER: i32 = SGXIOC_DETECT_DCAP_DRIVER as i32;
        const IOCTL_IS_EDMM_SUPPORTED: i32 = SGXIOC_IS_EDMM_SUPPORTED as i32;
    } else {
        const IOCTL_GET_EPID_GROUP_ID: u64 = SGXIOC_GET_EPID_GROUP_ID;
        const IOCTL_GEN_EPID_QUOTE: u64 = SGXIOC_GEN_EPID_QUOTE;
        const IOCTL_SELF_TARGET: u64 = SGXIOC_SELF_TARGET;
        const IOCTL_CREATE_REPORT: u64 = SGXIOC_CREATE_REPORT;
        const IOCTL_VERIFY_REPORT: u64 = SGXIOC_VERIFY_REPORT;

        const IOCTL_DETECT_DCAP_DRIVER: u64 = SGXIOC_DETECT_DCAP_DRIVER;
        const IOCTL_IS_EDMM_SUPPORTED: u64 = SGXIOC_IS_EDMM_SUPPORTED;
    }
}

// Copy from occlum/src/libos/src/fs/dev_fs/dev_sgx/mod.rs
#[repr(C)]
struct IoctlGenEPIDQuoteArg {
    report_data: sgx_report_data_t,    // Input
    quote_type: sgx_quote_sign_type_t, // Input
    spid: sgx_spid_t,                  // Input
    nonce: sgx_quote_nonce_t,          // Input
    sigrl_ptr: *const u8,              // Input (optional)
    sigrl_len: u32,                    // Input (optional)
    quote_buf_len: u32,                // Input
    quote_buf: *mut u8,                // Output
}

// Copy from occlum/src/libos/src/fs/dev_fs/dev_sgx/mod.rs
#[repr(C)]
struct IoctlCreateReportArg {
    target_info: *const sgx_target_info_t, // Input (optional)
    report_data: *const sgx_report_data_t, // Input (optional)
    report: *mut sgx_report_t,             // Output
}


pub struct EpidQuote {
    fd: c_int,
    group_id: sgx_epid_group_id_t,
    target_info: sgx_target_info_t,
}

impl EpidQuote {
    pub fn new() -> Self {
        let path =  CString::new("/dev/sgx").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), O_RDONLY) };
        if fd > 0 {
            Self {
                fd,
                group_id: sgx_epid_group_id_t::default(),
                target_info: sgx_target_info_t::default()
            }
        } else {
            panic!("Open /dev/sgx failed")
        }
    }

    pub fn get_group_id(&mut self) -> sgx_epid_group_id_t {
        let mut arg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();

        let ret = unsafe { libc::ioctl(self.fd, IOCTL_GET_EPID_GROUP_ID, &arg) };
        if ret < 0 {
            panic!("IOCTRL IOCTL_GET_EPID_GROUP_ID failed");
        } else {
            self.group_id = arg;
            arg
        }
    }

    pub fn get_target_info(&mut self) -> sgx_target_info_t {
        let mut arg: sgx_target_info_t = sgx_target_info_t::default();

        let ret = unsafe { libc::ioctl(self.fd, IOCTL_SELF_TARGET, &arg) };
        if ret < 0 {
            panic!("IOCTRL IOCTL_SELF_TARGET failed");
        } else {
            self.target_info = arg;
            arg
        }
    }

    pub fn get_epid_quote(&mut self, sigrl: Vec<u8>, spid: sgx_spid_t, report_data: sgx_report_data_t,
                          quote_type: sgx_quote_sign_type_t,
                         ) -> Vec<u8> {
        let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
        let mut os_rng = rand::thread_rng();
        os_rng.fill_bytes(&mut quote_nonce.rand);

        const RET_QUOTE_BUF_LEN: u32 = 2048;
        let mut quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
        let mut quote_len: u32 = 0;

        let mut args = IoctlGenEPIDQuoteArg{
            report_data,
            quote_type,
            spid,
            nonce: quote_nonce,
            sigrl_ptr: sigrl.as_ptr() as * const u8,
            sigrl_len: sigrl.len() as u32,
            quote_buf_len: quote_len,
            quote_buf: quote_buf.as_mut_ptr() as * mut u8,
        };

        let ret = unsafe { libc::ioctl(self.fd, IOCTL_GEN_EPID_QUOTE, &args) };
        if ret < 0 {
            panic!("IOCTRL IOCTL_GEN_EPID_QUOTE failed");
        } else {
            let mut quote = quote_buf.to_vec();
            quote.truncate(quote_len as usize);
            quote
        }
    }

    pub fn get_epid_report(&mut self, target_info: *const sgx_target_info_t,
                           report_data: *const sgx_report_data_t) -> sgx_report_t {

        let mut report = sgx_report_t::default();

        let mut args = IoctlCreateReportArg{
            target_info,
            report_data,
            report: &mut report as *mut sgx_report_t
        };

        let ret = unsafe { libc::ioctl(self.fd, IOCTL_CREATE_REPORT, &args) };
        if ret < 0 {
            panic!("IOCTRL IOCTL_GEN_EPID_QUOTE failed");
        } else {
            report
        }
    }

}