#![no_main]

use libfuzzer_sys::fuzz_target;
use routeguard_awg::{parse_awg_from_conf, validate_awg_params};

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let params = parse_awg_from_conf(&text);
    let _ = validate_awg_params(&params);
});
