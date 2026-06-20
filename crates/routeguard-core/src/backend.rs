use serde::{Deserialize, Serialize};

/// Active tunnel transport backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    #[default]
    WireGuardNt,
    Awg,
}

impl BackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WireGuardNt => "wireguard_nt",
            Self::Awg => "awg",
        }
    }
}

/// User preference for tunnel backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TunnelBackendPreference {
    #[default]
    Auto,
    WireGuardNt,
    Awg,
}

/// Profile kind derived from configuration content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    #[default]
    Standard,
    Awg,
}
