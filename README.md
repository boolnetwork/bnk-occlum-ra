# Use Rust with Occlum

This directory contains scripts and source code to demonstrate how to
compile and run Rust programs on Occlum.

## occlum-cargo and occlum-rustc

We introduce cargo and rustc wrappers called occlum-cargo and occlum-rustc
respectively. They wrap the original commands with options specific to occlum.
Refer to tools/toolchains/rust/build.sh for more information.

## rust\_app

This directory contains source code of a Rust program with a cpp FFI. The cpp
interface increments the input by one. Rust code calls the function and
displays the result on the terminal.

One can use occlum-cargo in the way cargo is used. In the rust\_app directory,
calling ```occlum-cargo build``` will build the demo and ```occlum-cargo run```
will run the demo on host. To run the demo in occlum, run:
```
run_rust_demo_on_occlum.sh
```
The output will be displayed on the terminal:
```
5 + 1 = 6
```

# USEAGE



/occlum-ra/src/lib.rs:

```
// generate cert and key for tls server
pub fn generate_cert_key() -> Result<(Vec<u8>,Vec<u8>),String>{
    println!("start generate_cert_key");
    generate_cert("".to_string())
}

// verify tls cert
pub fn verify_cert(cert:&[u8], now: u64) -> Result<EnclaveFields, String>{
    verify(cert,now)
}

// create dcap report
pub fn create_dcap_report(additional_info:Vec<u8>) -> Vec<u8>{
    let report = DcapAttestation::create_report(&additional_info).unwrap();
    report.into_payload()
}

// verify dcap report
pub fn verify_dcap_report(report: Vec<u8>, now: u64)  -> Result<EnclaveFields, String>{
    verify_only_report(&report, now)
}

```


test pass in HW mode

![image](https://user-images.githubusercontent.com/29329767/216571968-1ddafbe4-bcdc-4ac2-b651-5fb65f846522.png)
