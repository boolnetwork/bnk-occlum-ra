use occlum_ra;

use occlum_ra::{generate_cert_key, generate_epid, get_fingerprint, get_fingerprint_epid, verify_cert};
use std::time::{SystemTime, UNIX_EPOCH};
use occlum_ra::attestation::{AttestationReport, AttestationStyle, IasAttestation};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use rocksdb::{DB, Options};
pub fn rocksdb(){
    let path = "/rocks";
    {
        let db = DB::open_default(path).unwrap();

        match db.get(b"my key") {
            Ok(Some(value)) => println!("retrieved value {}", String::from_utf8(value).unwrap()),
            Ok(None) => println!("value not found"),
            Err(e) => println!("operational problem encountered: {}", e),
        }

        let put_result = db.put(b"my key", b"rocksdb my value");
        println!("put_result {:?}",put_result);

    }
}

fn main() {
    rocksdb();
    let read_result = std::fs::read_to_string("/test.config");
    println!("read_result {:?}",read_result);

    let write_result = std::fs::write("/test.config","aaaaaaaa");
    println!("write_result {:?}",write_result);


}
