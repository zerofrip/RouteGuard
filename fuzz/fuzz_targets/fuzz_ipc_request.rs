#![no_main]

use libfuzzer_sys::fuzz_target;
use routeguard_core::ipc::IpcRequest;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let _ = serde_json::from_slice::<IpcRequest>(data);
});
