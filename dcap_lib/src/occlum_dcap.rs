use std::ffi::CString;
use crate::prelude::*;

const SGXIOC_GET_DCAP_QUOTE_SIZE: u64 = 0x80047307;
const SGXIOC_GEN_DCAP_QUOTE: u64 = 0xc0187308;
const SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE: u64 = 0x80047309;
const SGXIOC_VER_DCAP_QUOTE: u64 = 0xc030730a;

cfg_if::cfg_if! {
    if #[cfg(target_env = "musl")] {
        const IOCTL_GET_DCAP_QUOTE_SIZE: i32 = SGXIOC_GET_DCAP_QUOTE_SIZE as i32;
        const IOCTL_GEN_DCAP_QUOTE: i32 = SGXIOC_GEN_DCAP_QUOTE as i32;
        const IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE: i32 = SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE as i32;
        const IOCTL_VER_DCAP_QUOTE: i32 = SGXIOC_VER_DCAP_QUOTE as i32;
    } else {
        const IOCTL_GET_DCAP_QUOTE_SIZE: u64 = SGXIOC_GET_DCAP_QUOTE_SIZE;
        const IOCTL_GEN_DCAP_QUOTE: u64 = SGXIOC_GEN_DCAP_QUOTE;
        const IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE: u64 = SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE;
        const IOCTL_VER_DCAP_QUOTE: u64 = SGXIOC_VER_DCAP_QUOTE;
    }
}


// Copy from occlum/src/libos/src/fs/dev_fs/dev_sgx/mod.rs
//#[allow(dead_code)]
#[repr(C)]
pub struct IoctlGenDCAPQuoteArg {
    pub report_data: *const sgx_report_data_t, // Input
    pub quote_size: *mut u32,                  // Input/output
    pub quote_buf: *mut u8,                    // Output
}

// Copy from occlum/src/libos/src/fs/dev_fs/dev_sgx/mod.rs
//#[allow(dead_code)]
#[repr(C)]
pub struct IoctlVerDCAPQuoteArg {
    pub quote_buf: *const u8,                               // Input
    pub quote_size: u32,                                    // Input
    pub collateral_expiration_status: *mut u32,             // Output
    pub quote_verification_result: *mut sgx_ql_qv_result_t, // Output
    pub supplemental_data_size: u32,                        // Input (optional)
    pub supplemental_data: *mut u8,                         // Output (optional)
}

pub struct DcapQuote {
    fd: c_int,
    quote_size: u32,
    supplemental_size: u32,
}

impl DcapQuote {
    pub fn new() -> Self {
        let path =  CString::new("/dev/sgx").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), O_RDONLY) };
        if fd > 0 {
            Self {
                fd: fd,
                quote_size: 0,
                supplemental_size: 0,
            }
        } else {
            panic!("Open /dev/sgx failed")
        }
    }

    pub fn get_quote_size(&mut self) -> u32 {
        let size: u32 = 0;
        let ret = unsafe { libc::ioctl(self.fd, IOCTL_GET_DCAP_QUOTE_SIZE, &size) };
        if ret < 0 {
            panic!("IOCTRL IOCTL_GET_DCAP_QUOTE_SIZE failed");
        } else {
            self.quote_size = size;
            size
        }
    }

    pub fn generate_quote(&mut self, quote_buf: *mut u8,  report_data: *const sgx_report_data_t) -> Result<i32, &'static str> {
        let quote_arg: IoctlGenDCAPQuoteArg = IoctlGenDCAPQuoteArg {
            report_data: report_data,
            quote_size: &mut self.quote_size,
            quote_buf: quote_buf,
        };

        let ret = unsafe { libc::ioctl(self.fd, IOCTL_GEN_DCAP_QUOTE, &quote_arg) };
        if ret < 0 {
            Err("IOCTRL IOCTL_GEN_DCAP_QUOTE failed")
        } else {
            Ok( 0 )
        }
    }

    pub fn get_supplemental_data_size(&mut self) -> u32 {
        let size: u32 = 0;
        let ret = unsafe { libc::ioctl(self.fd, IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE, &size) };
        if ret < 0 {
            panic!("IOCTRL IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE failed");
        } else {
            self.supplemental_size = size;
            size
        }
    }

    pub fn verify_quote(&mut self, verify_arg: *mut IoctlVerDCAPQuoteArg) -> Result<i32, &'static str> {
        let ret = unsafe { libc::ioctl(self.fd, IOCTL_VER_DCAP_QUOTE, verify_arg) };
        if ret < 0 {
            println!("ret = {}", ret);
            Err("IOCTRL IOCTL_VER_DCAP_QUOTE failed")
        } else {
            Ok( 0 )
        }
    }

    pub fn close(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

const SGXIOC_GET_KEY: u64 = 3222303499;

cfg_if::cfg_if! {
    if #[cfg(target_env = "musl")] {
        const IOCTL_GET_KEY: i32 = SGXIOC_GET_KEY as i32;
    } else {
        const IOCTL_GET_KEY: u64 = SGXIOC_GET_KEY;
    }
}

#[repr(C)]
pub struct IoctlGetKeyArg {
    key_request: *const sgx_key_request_t, // Input
    key: *mut sgx_key_128bit_t,            // Output
}

pub struct GETKEY {
    fd: c_int,
}

impl GETKEY {
    pub fn new() -> Self {
        let path =  CString::new("/dev/sgx").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), O_RDONLY) };
        if fd > 0 {
            Self {
                fd: fd,
            }
        } else {
            panic!("Open /dev/sgx failed")
        }
    }

    pub fn get_key(&mut self, request: *const sgx_key_request_t) -> Result<sgx_key_128bit_t, &'static str> {
        let mut key = sgx_key_128bit_t::default();

        let key_args: IoctlGetKeyArg = IoctlGetKeyArg {
            key_request: request,
            key: &mut key
        };

        let ret = unsafe { libc::ioctl(self.fd, IOCTL_GET_KEY, &key_args) };
        if ret < 0 {
            Err("IOCTRL IOCTL_GET_KEY failed")
        } else {
            Ok( key )
        }
    }
}

pub fn get_key(report: *const sgx_report_body_t) -> sgx_key_128bit_t{
    let mut get_key = GETKEY::new();

    let attribute_mask = sgx_attributes_t {
        flags: TSEAL_DEFAULT_FLAGSMASK,
        xfrm: 0,
    };
    // hack the key_id
    let key_id = sgx_key_id_t {
        id: [0u8; SGX_KEYID_SIZE],
    };
    let key_policy: u16 = SGX_KEYPOLICY_MRENCLAVE;
    let mut key_request = sgx_key_request_t {
        key_name: SGX_KEYSELECT_SEAL,
        key_policy,
        isv_svn: 0u16,
        reserved1: 0u16,
        cpu_svn: unsafe { (*report).cpu_svn },
        attribute_mask,
        key_id,
        misc_mask: TSEAL_DEFAULT_MISCMASK,
        config_svn: 0u16,
        reserved2: [0u8; SGX_KEY_REQUEST_RESERVED2_BYTES],
    };

    let key = get_key.get_key(&mut key_request).unwrap();
    key
}