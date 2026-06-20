//! AmneziaWG tunnel backend — uses amneziawg `tunnel.dll` via shared WGNT adapter stack.

#[cfg(windows)]
mod imp {
    use std::path::PathBuf;
    use std::sync::Arc;

    use async_trait::async_trait;
    use routeguard_awg::{parse_awg_from_conf, validate_awg_params_strict};
    use routeguard_core::backend::BackendKind;
    use routeguard_core::config::TunnelConfig;
    use routeguard_core::error::{Result, RouteGuardError};
    use routeguard_core::tunnel::{TunnelBackend, TunnelHandle, TunnelStats, TunnelStatus};

    use crate::integrity;
    use crate::routes::RouteTableManager;
    use crate::tunnel::WireGuardNtBackend;
    use crate::wgnt::WgntLibrary;

    pub struct AwgBackend {
        inner: WireGuardNtBackend,
    }

    impl Default for AwgBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AwgBackend {
        pub fn new() -> Self {
            let dll = resolve_awg_dll_path();
            integrity::verify_or_warn(&dll);
            Self {
                inner: WireGuardNtBackend::with_dll_path(dll),
            }
        }

        pub fn with_routes(routes: Arc<RouteTableManager>) -> Self {
            Self {
                inner: WireGuardNtBackend::with_routes_and_dll(routes, resolve_awg_dll_path()),
            }
        }
    }

    fn resolve_awg_dll_path() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("tunnel.dll")))
            .unwrap_or_else(|| PathBuf::from("tunnel.dll"))
    }

    pub fn probe_awg_library() -> bool {
        WgntLibrary::load(resolve_awg_dll_path()).is_ok()
    }

    #[async_trait]
    impl TunnelBackend for AwgBackend {
        fn name(&self) -> &str {
            "amneziawg-native"
        }

        async fn up(&self, config: &TunnelConfig) -> Result<TunnelHandle> {
            let text = std::fs::read_to_string(&config.config_path)
                .map_err(|e| RouteGuardError::Config(format!("read conf: {e}")))?;
            let awg = parse_awg_from_conf(&text);
            validate_awg_params_strict(&awg)
                .map_err(|issues| RouteGuardError::Config(format!("AWG validation: {issues:?}")))?;

            let mut handle = self.inner.up(config).await?;
            handle.backend = BackendKind::Awg;
            tracing::info!(
                "AWG tunnel {} connected (if_index={})",
                handle.name,
                handle.if_index
            );
            Ok(handle)
        }

        async fn down(&self, handle: &TunnelHandle) -> Result<()> {
            self.inner.down(handle).await
        }

        fn status(&self, handle: &TunnelHandle) -> TunnelStatus {
            self.inner.status(handle)
        }

        fn stats(&self, handle: &TunnelHandle) -> Result<TunnelStats> {
            self.inner.stats(handle)
        }
    }
}

#[cfg(windows)]
pub use imp::{probe_awg_library, AwgBackend};

#[cfg(not(windows))]
use async_trait::async_trait;
#[cfg(not(windows))]
use routeguard_core::config::TunnelConfig;
#[cfg(not(windows))]
use routeguard_core::error::{Result, RouteGuardError};
#[cfg(not(windows))]
use routeguard_core::tunnel::{
    TunnelBackend, TunnelHandle, TunnelLifecycle, TunnelStats, TunnelStatus,
};

#[cfg(not(windows))]
pub struct AwgBackend;

#[cfg(not(windows))]
impl Default for AwgBackend {
    fn default() -> Self {
        Self
    }
}

#[cfg(not(windows))]
impl AwgBackend {
    pub fn new() -> Self {
        Self
    }

    pub fn with_routes(_routes: std::sync::Arc<crate::routes::RouteTableManager>) -> Self {
        Self
    }
}

#[cfg(not(windows))]
pub fn probe_awg_library() -> bool {
    false
}

#[cfg(not(windows))]
#[async_trait]
impl TunnelBackend for AwgBackend {
    fn name(&self) -> &str {
        "amneziawg-native"
    }

    async fn up(&self, _config: &TunnelConfig) -> Result<TunnelHandle> {
        Err(RouteGuardError::UnsupportedPlatform)
    }

    async fn down(&self, _handle: &TunnelHandle) -> Result<()> {
        Err(RouteGuardError::UnsupportedPlatform)
    }

    fn status(&self, _handle: &TunnelHandle) -> TunnelStatus {
        TunnelLifecycle::Disconnected
    }

    fn stats(&self, _handle: &TunnelHandle) -> Result<TunnelStats> {
        Err(RouteGuardError::UnsupportedPlatform)
    }
}
