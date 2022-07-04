use tiny_keccak::{Keccak, Hasher};
use std::thread;
use std::time::Instant;
use structopt::StructOpt;

uint::construct_uint! {
	pub struct U256(4);
}

extern crate hex;

#[derive(StructOpt)]
struct Args {
    #[structopt(default_value = "1")]
    threads: usize,
}

fn hash(selector: &[u8; 4], salt: &[u8; 4], m: u64) -> u64 {
    let mut hasher = Keccak::v256();
	hasher.update(selector);
    hasher.update(salt);
    let mut res = [0u8; 32];
    hasher.finalize(&mut res);
    (U256::from(res) % U256::from(m)).as_u64()
}

fn main() {
    let args = Args::from_args();
    assert!(args.threads < 16, "Too many threads");

    let signatures = [
        "eq(uint256,uint256)",
        "lt(uint256,uint256)",
        "gt(uint256,uint256)",
        "and(uint256,uint256)",
        "or(uint256,uint256)",
        "xor(uint256,uint256)",
        "add(uint256,uint256)",
        "sub(uint256,uint256)",
        "mul(uint256,uint256)",
        "div(uint256,uint256)",
        
        "eq2(uint256,uint256)",
        "lt2(uint256,uint256)",
        "gt2(uint256,uint256)",
        "and2(uint256,uint256)",
        "or2(uint256,uint256)",
        "xor2(uint256,uint256)",
        "add2(uint256,uint256)",
        "sub2(uint256,uint256)",
        // "mul2(uint256,uint256)",
        // "div2(uint256,uint256)",
    ];

    let all_selectors = signatures.iter().map(|sig| {
        let mut hasher = Keccak::v256();
	    hasher.update(sig.as_bytes());
        let mut res = [0u8; 4];
        hasher.finalize(&mut res);
        res
    }).collect::<Vec<[u8; 4]>>();

    println!("Selectors = {:?}", all_selectors);

    let args_threads = args.threads;
    let mut handles = vec![];
    for ti in 0..args.threads as u8 {
        let selectors = signatures.iter().map(|sig| {
            let mut hasher = Keccak::v256();
	        hasher.update(sig.as_bytes());
            let mut res = [0u8; 4];
            hasher.finalize(&mut res);
            res
        }).collect::<Vec<[u8; 4]>>();

        handles.push(Some(thread::spawn(move || {
            let mut index = 0u64;
            let mut keccaks = 0u64;
            let mut reported_index = 0u64;
            let mut reported_keccak = 0u64;
            let mut last = Instant::now();
            let first = last;
            
            for i1 in 0..=15u8 {
                for i2 in 0..=255u8 {
                    let ms = last.elapsed().as_millis() as u64;
                    if ms > 3000 {
                        println!(
                            "Thread #{:x}: iteration {}M ({} KSalt/s, {} MKeccak/s)\r",
                            ti,
                            (index / 1000) as f64 / 1000.0,
                            ((index - reported_index) * 1000 / (1 + ms)) as f64 / 1000.0,
                            ((keccaks - reported_keccak) / (1 + ms)) as f64 / 1000.0
                        );
                        last = Instant::now();
                        reported_index = index;
                        reported_keccak = keccaks;
                    }
                    
                    for i3 in 0..=255u8 {
                        for i4 in 0..=255u8 {
                            index += 1;
                            let salt = [(ti << 4) | i1, i2, i3, i4];
                            
                            let mut mask = 0u128;
                            for i in 0..selectors.len() {
                                keccaks += 1;
                                let hash = hash(&selectors[i], &salt, selectors.len() as u64);
                                let bit = 1u128 << hash as u128;
                                if mask & bit != 0 {
                                    break;
                                }
                                mask |= 1 << hash;
                            }
                            
                            if mask + 1 == 1 << selectors.len() {
                                let hashes = selectors.iter().map(|selector| {
                                    hash(&selector, &salt, selectors.len() as u64)
                                }).collect::<Vec<u64>>();
    
                                println!(
                                    "Found salt 0x{:x} in {} seconds after {}M iterations",
                                    u32::from_be_bytes(salt),
                                    first.elapsed().as_secs(),
                                    (index * args_threads as u64 / 1000) as f64 / 1000.0
                                );
                                println!("Results: {:?}", hashes);

                                let mut lookup = U256::from(0);
                                for i in 0..hashes.len() {
                                    lookup = lookup | (U256::from(i) << (248 - hashes[i] * 8));
                                }
                                println!("Lookup: 0x{:064x}", lookup);
                                
                                std::process::exit(0);
                            }
                        }
                    }
                }
            }
        })));
    }

    for i in 0..handles.len() {
        handles[i].take().map(std::thread::JoinHandle::join);
    }
}
