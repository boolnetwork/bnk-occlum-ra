use std::sync::Arc;
use occlum_ra;

use occlum_ra::{generate_cert_key, generate_epid, get_fingerprint, get_fingerprint_epid, verify_cert};
use std::time::{SystemTime, UNIX_EPOCH};
use occlum_ra::attestation::{AttestationReport, AttestationStyle, IasAttestation};
use db_wrap::{DbWrap, RocksdbOptions};
use serde::{Serialize, Deserialize};
use serde_json;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

const DB_PATH: &str = "./host/data";
const KEY_PATH: &str = "key";
const DEFAULT_DATA_LV: u8 = 3;

#[derive(Clone, Serialize, Deserialize)]
struct Data {
    pub value: u64,
    pub useless: Vec<u8>,
    pub useless2: Vec<u8>,
    pub useless3: Vec<u8>,
}

fn main() {
    env_logger::init();

    // let read_result = std::fs::read_to_string("/host/test.config").unwrap();
    // println!("read_result {:?}",read_result);

    let db_wrap = Arc::new(DbWrap::new(&DB_PATH, RocksdbOptions::default().into()));
    for i in 0..15 {
        let db = db_wrap.clone();
        std::thread::spawn(move || {
            loop {
                let key = format!("{}-{}","key",i);
                let value = match db
                    .get(key.clone(), KEY_PATH)
                {
                    Ok(data) => {
                        match data {
                            Some(value_slive) => {
                                let data: Data = serde_json::from_slice(&value_slive).unwrap();
                                data.value}
                                // let hex_str = hex::decode(value_slive).unwrap();
                                // let n: u64 = u64::from_le_bytes(hex_str.try_into().unwrap());
                                //n }
                            None => {
                                0u64
                            }
                        }
                    } ,
                    Err(e) => { println!("put error {:?}",e); 0u64 },
                };

                let new_value = value + 1;
                let data:Data = Data{ value:new_value, useless: vec![8u8;6887],
                    useless2: vec![12u8;200], useless3: vec![99u8;588] };
                let hex_string = serde_json::to_vec(&data).unwrap();
                //let hex_string = hex::encode(new_value.to_le_bytes());

                match db.put(key, hex_string , DEFAULT_DATA_LV, false, KEY_PATH){
                    Ok(_) => { println!("put {} successful",new_value)}
                    Err(e) => {println!("put error {:?}",e)}
                }
                std::thread::sleep(std::time::Duration::from_millis(200));

            }
        });
    }

    std::thread::sleep(std::time::Duration::from_secs(200));



    println!("start");
    let cert_der = match generate_cert_key() {
        Err(e) => panic!("error: {:?}", e),
        Ok((a, b)) => b,
    };

    let res = verify_cert(&cert_der);

    println!("verify_cert result {:?}", res);

    let result = IasAttestation::create_report("epid".as_bytes()).unwrap();
    let epid_attestation = AttestationReport{
        style: AttestationStyle::EPID,
        data: result.into_payload()
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let result = IasAttestation::verify(&epid_attestation,now);
    println!("verify epid result {:?}", result);

    let fingerprint = get_fingerprint_epid(2);
    println!("fingerprint {:?}",fingerprint);
    let fingerprint = get_fingerprint(2);
    println!("fingerprint {:?}",fingerprint);
}
