use occlum_ra;

use std::time::{SystemTime, UNIX_EPOCH};
use occlum_ra::{generate_cert_key, verify_cert};

fn main() {
    println!("start");
    let cert_der = match generate_cert_key() {
        Err(e) => panic!("error: {:?}",e),
        Ok((a,b)) => b,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let res = verify_cert(&cert_der, now);

    println!("verify_cert result {:?}",res);

}
