#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(windows)]
use routeguard_platform::wgnt::config::parse_conf_text;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    #[cfg(windows)]
    {
        let _ = parse_conf_text(&text);
    }
    #[cfg(not(windows))]
    {
        let _ = text;
    }
});
