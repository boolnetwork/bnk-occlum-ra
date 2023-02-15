pub use std::boxed::Box;
pub use libc::{open, ioctl, close, c_void, c_int, O_RDONLY};

// Defined in "occlum/deps/rust-sgx-sdk/sgx_types"
pub use sgx_types::{
    sgx_quote_header_t, sgx_report_data_t, sgx_ql_qv_result_t, sgx_report_body_t, sgx_quote3_t, sgx_key_request_t,
    sgx_key_128bit_t, uint16_t, sgx_key_id_t, SGX_KEYID_SIZE, SGX_KEYPOLICY_MRSIGNER, TSEAL_DEFAULT_MISCMASK,
    SGX_KEY_REQUEST_RESERVED2_BYTES, sgx_attributes_t, TSEAL_DEFAULT_FLAGSMASK, SGX_KEYSELECT_SEAL, SGX_KEYPOLICY_MRENCLAVE
};
