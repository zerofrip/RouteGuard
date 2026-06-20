use thiserror::Error;

pub type WgntResult<T> = Result<T, WgntError>;

#[derive(Debug, Error)]
pub enum WgntError {
    #[error("wireguard.dll not found at {path}")]
    DllNotFound { path: String },

    #[error("failed to load wireguard.dll: {0}")]
    DllLoad(String),

    #[error("missing export {symbol} in wireguard.dll")]
    MissingExport { symbol: String },

    #[error("WireGuard API call {api} failed: {message} (win32={code})")]
    Api {
        api: &'static str,
        message: String,
        code: u32,
    },

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("adapter handle is null")]
    NullAdapter,

    #[error("handshake timeout after {secs}s")]
    HandshakeTimeout { secs: u64 },

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("platform not supported")]
    UnsupportedPlatform,
}

impl WgntError {
    #[cfg(windows)]
    pub fn last_error(api: &'static str) -> Self {
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        WgntError::Api {
            api,
            message: format_win32_error(code),
            code,
        }
    }
}

#[cfg(windows)]
fn format_win32_error(code: u32) -> String {
    if code == 0 {
        return "unknown error".into();
    }
    format!("Win32 error {code}")
}

#[cfg(not(windows))]
fn format_win32_error(_code: u32) -> String {
    "n/a".into()
}
