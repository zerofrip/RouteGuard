#![no_main]

use libfuzzer_sys::fuzz_target;
use routeguard_lwo::deobfuscate;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    let mut buf = data.to_vec();
    let key = [0u8; 32];
    deobfuscate(&mut buf, &key);
});
