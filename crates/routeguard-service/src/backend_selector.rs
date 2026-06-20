//! Select WireGuardNT vs AWG backend per profile and config.

use std::path::Path;

use routeguard_awg::{is_awg_profile, AWG_PARAM_NAMES};
use routeguard_core::backend::{BackendKind, TunnelBackendPreference};
use routeguard_core::config::TunnelConfig;
use routeguard_core::error::{Result, RouteGuardError};
use routeguard_core::profile::ResolvedBackend;
use routeguard_core::tunnel::{TunnelBackend, TunnelHandle, TunnelStats, TunnelStatus};
use routeguard_platform::{probe_awg_library, AwgBackend, WireGuardNtBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    Wgnt,
    Awg,
}

pub struct TunnelBackendSelector {
    wgnt: WireGuardNtBackend,
    awg: AwgBackend,
}

impl TunnelBackendSelector {
    pub fn new(wgnt: WireGuardNtBackend, awg: AwgBackend) -> Self {
        Self { wgnt, awg }
    }

    pub fn probe_awg(&self) -> bool {
        probe_awg_library()
    }

    pub fn awg_dll_present(&self) -> bool {
        probe_awg_library()
    }

    pub fn awg_param_names(&self) -> &'static [&'static str] {
        AWG_PARAM_NAMES
    }

    pub fn resolve(&self, config: &TunnelConfig) -> Result<(ResolvedBackend, BackendChoice)> {
        let conf_has_awg = read_conf_has_awg(&config.config_path);

        let (kind, fallback, reason) = match config.backend {
            TunnelBackendPreference::WireGuardNt => (BackendKind::WireGuardNt, false, None),
            TunnelBackendPreference::Awg => {
                if !probe_awg_library() {
                    return Err(RouteGuardError::Platform(
                        "backend=awg requires amneziawg tunnel.dll".into(),
                    ));
                }
                (BackendKind::Awg, false, None)
            }
            TunnelBackendPreference::Auto => {
                if conf_has_awg && probe_awg_library() {
                    (BackendKind::Awg, false, None)
                } else if conf_has_awg && !probe_awg_library() {
                    if config.require_awg {
                        return Err(RouteGuardError::Platform(
                            "require_awg set but tunnel.dll not available".into(),
                        ));
                    }
                    (
                        BackendKind::WireGuardNt,
                        true,
                        Some("awg_params_present_dll_missing".into()),
                    )
                } else {
                    (BackendKind::WireGuardNt, false, None)
                }
            }
        };

        let choice = match kind {
            BackendKind::Awg => BackendChoice::Awg,
            BackendKind::WireGuardNt => BackendChoice::Wgnt,
        };

        Ok((
            ResolvedBackend {
                kind,
                fallback,
                fallback_reason: reason,
            },
            choice,
        ))
    }

    pub async fn up(&self, choice: BackendChoice, config: &TunnelConfig) -> Result<TunnelHandle> {
        match choice {
            BackendChoice::Wgnt => self.wgnt.up(config).await,
            BackendChoice::Awg => self.awg.up(config).await,
        }
    }

    pub async fn down(&self, choice: BackendChoice, handle: &TunnelHandle) -> Result<()> {
        match choice {
            BackendChoice::Wgnt => self.wgnt.down(handle).await,
            BackendChoice::Awg => self.awg.down(handle).await,
        }
    }

    pub fn stats(&self, choice: BackendChoice, handle: &TunnelHandle) -> Result<TunnelStats> {
        match choice {
            BackendChoice::Wgnt => self.wgnt.stats(handle),
            BackendChoice::Awg => self.awg.stats(handle),
        }
    }

    pub fn status(&self, choice: BackendChoice, handle: &TunnelHandle) -> TunnelStatus {
        match choice {
            BackendChoice::Wgnt => self.wgnt.status(handle),
            BackendChoice::Awg => self.awg.status(handle),
        }
    }

    pub fn choice_for(&self, kind: BackendKind) -> BackendChoice {
        match kind {
            BackendKind::Awg => BackendChoice::Awg,
            BackendKind::WireGuardNt => BackendChoice::Wgnt,
        }
    }
}

fn read_conf_has_awg(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|t| is_awg_profile(&t))
        .unwrap_or(false)
}

pub fn probe_awg_available() -> bool {
    probe_awg_library()
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeguard_core::backend::{BackendKind, TunnelBackendPreference};
    use routeguard_core::config::TunnelConfig;
    use routeguard_platform::{AwgBackend, WireGuardNtBackend};

    #[test]
    fn auto_selects_wgnt_for_standard_conf() {
        let dir = std::env::temp_dir().join("rg_awg_test_std");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("std.conf");
        std::fs::write(
            &path,
            "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
        )
        .unwrap();

        let cfg = TunnelConfig {
            name: "t".into(),
            config_path: path,
            mtu: 1420,
            backend: TunnelBackendPreference::Auto,
            require_awg: false,
            transport: Default::default(),
        };

        let sel = TunnelBackendSelector::new(WireGuardNtBackend::new(), AwgBackend::new());
        let (resolved, _) = sel.resolve(&cfg).unwrap();
        assert_eq!(resolved.kind, BackendKind::WireGuardNt);
        assert!(!resolved.fallback);
    }

    #[test]
    fn auto_awg_without_dll_falls_back_on_linux() {
        let dir = std::env::temp_dir().join("rg_awg_test_awg");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("awg.conf");
        std::fs::write(
            &path,
            "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nJc = 4\nJmin = 10\nJmax = 100\n",
        )
        .unwrap();

        let cfg = TunnelConfig {
            name: "t".into(),
            config_path: path,
            mtu: 1420,
            backend: TunnelBackendPreference::Auto,
            require_awg: false,
            transport: Default::default(),
        };

        let sel = TunnelBackendSelector::new(WireGuardNtBackend::new(), AwgBackend::new());
        let (resolved, _) = sel.resolve(&cfg).unwrap();
        assert_eq!(resolved.kind, BackendKind::WireGuardNt);
        #[cfg(not(windows))]
        assert!(resolved.fallback);
    }
}
