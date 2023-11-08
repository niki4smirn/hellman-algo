use sha256::digest;
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;

use rand::Rng;

const CHAR_RANGE: std::ops::Range<u8> = b'a'..b'z';
const PWD_LEN: usize = 4;

// because passwords are 'a'..'z' 4 chars long
const PRECALC_ITERS: usize = 1 << 10;
const CHAIN_LEN: usize = 1 << 10;

fn random_pass() -> String {
    let mut rng = rand::thread_rng();
    let mut pass = String::new();
    for _ in 0..PWD_LEN {
        pass.push(rng.gen_range(CHAR_RANGE) as char);
    }
    pass
}

fn read_map() -> HashMap<String, String> {
    let mut file = std::fs::File::open("chain").unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    let mut map = HashMap::new();
    for line in buf.split(|&c| c == b'\n') {
        if line.len() == 0 {
            continue;
        }
        let mut iter = line.split(|&c| c == b' ');
        let pwd_hash = iter.next().unwrap();
        let pwd = iter.next().unwrap();
        map.insert(
            String::from_utf8(pwd_hash.to_vec()).unwrap(),
            String::from_utf8(pwd.to_vec()).unwrap(),
        );
    }
    map
}

fn write_map(map: &HashMap<String, String>) {
    let mut file = std::fs::File::create("chain").unwrap();
    let mut buf = Vec::new();
    for (k, v) in map {
        buf.extend_from_slice(k.as_bytes());
        buf.extend_from_slice(b" ");
        buf.extend_from_slice(v.as_bytes());
        buf.extend_from_slice(b"\n");
    }
    file.write_all(&buf).unwrap();
}

fn truncate(pwd_hash: &[u8]) -> String {
    let mut pwd = String::new();
    let mut hash_part = 0;
    // WARNING! works only for PWD_LEN < 8
    for i in 0..PWD_LEN {
        hash_part = (hash_part << 8) | pwd_hash[i] as u64;
    }
    for _ in 0..PWD_LEN {
        pwd.push(((hash_part % 26) as u8 + b'a') as char);
        hash_part /= 26;
    }
    pwd
}

fn step(pwd: &str) -> (String, String) {
    let pwd_hash = digest(pwd.as_bytes());
    let new_pwd = truncate(pwd_hash.as_bytes());
    (pwd_hash, new_pwd)
}

fn precalc(start_pwds: &[String]) {
    let mut map = HashMap::new();
    for start_pwd in start_pwds {
        let mut pwd = start_pwd.to_string();
        let mut pwd_hash = String::new();
        for _ in 0..CHAIN_LEN {
            (pwd_hash, pwd) = step(&pwd);
        }
        map.insert(pwd_hash, start_pwd.clone());
    }
    write_map(&map);
}

fn find_in_chain(target_pwd_hash: &[u8], start_pwd: &str) -> Option<String> {
    let mut pwd = start_pwd.to_string();
    let mut pwd_hash;
    for _ in 0..CHAIN_LEN {
        let prev_pwd = pwd.clone();
        (pwd_hash, pwd) = step(&pwd);
        if pwd_hash.as_bytes() == target_pwd_hash {
            return Some(prev_pwd);
        }
    }
    None
}

fn hack(target_pwd_hash: &[u8], map: &HashMap<String, String>) -> Option<String> {
    if map.contains_key(&String::from_utf8(target_pwd_hash.to_vec()).unwrap()) {
        if let Some(pwd) = map.get(&String::from_utf8(target_pwd_hash.to_vec()).unwrap()) {
            return Some(pwd.clone());
        }
    }
    let mut pwd = truncate(target_pwd_hash);
    let mut pwd_hash;
    for _ in 0..(CHAIN_LEN - 1) {
        (pwd_hash, pwd) = step(&pwd);
        if map.contains_key(&pwd_hash) {
            match find_in_chain(target_pwd_hash, &map.get(&pwd_hash).unwrap()) {
                Some(pwd) => return Some(pwd),
                None => continue,
            }
        }
    }
    None
}

fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() >= 2 && args[1] == "--precalc" {
        let mut start_pwds = Vec::new();
        for _ in 0..PRECALC_ITERS {
            start_pwds.push(random_pass());
        }
        precalc(start_pwds.as_slice());
    } else {
        const TO_HACK_COUNT: usize = 10;
        for _ in 0..TO_HACK_COUNT {
            let pass = random_pass();
            let to_hack = digest(pass.as_bytes());
            println!("to hack: {}", pass);
            let map = read_map();
            let pwd = hack(to_hack.as_bytes(), &map);
            match pwd {
                Some(pwd) => println!("found: {}", pwd),
                None => println!("not found"),
            }
        }
    }
}
