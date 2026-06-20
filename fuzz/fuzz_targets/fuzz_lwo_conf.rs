#![no_main]

use libfuzzer_sys::fuzz_target;
use routeguard_core::transport::{parse_routeguard_section, transport_hints_from_conf};
use routeguard_lwo::parse_lwo_keys;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let _ = parse_routeguard_section(&text);
    let _ = transport_hints_from_conf(&text);
    let _ = parse_lwo_keys(&text);
});
