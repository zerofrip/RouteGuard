//! WFP application ID helpers.

use std::path::Path;

/// Normalize an executable path for WFP app conditions.
pub fn normalize_app_path(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\")
}

#[cfg(windows)]
pub fn app_path_for_filter(path: &str) -> String {
    normalize_app_path(std::path::Path::new(path))
}

#[cfg(not(windows))]
pub fn app_path_for_filter(path: &str) -> String {
    path.to_string()
}
