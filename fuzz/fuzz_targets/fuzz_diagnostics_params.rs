#![no_main]

use libfuzzer_sys::fuzz_target;
use routeguard_core::observability::DiagnosticsExportParams;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }
    if let Ok(params) = serde_json::from_slice::<DiagnosticsExportParams>(data) {
        let tier = params.tier.as_str();
        let _ = tier == "sanitized" || tier == "support" || tier == "full" || !tier.is_empty();
    }
});
