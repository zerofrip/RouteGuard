//! Tunnel profile vault types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::backend::{BackendKind, ProfileKind, TunnelBackendPreference};
use crate::transport::TunnelTransportConfig;

/// Stored tunnel profile metadata + conf reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelProfile {
    pub id: Uuid,
    pub name: String,
    pub kind: ProfileKind,
    #[serde(default)]
    pub backend: TunnelBackendPreference,
    pub config_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TunnelTransportConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_from: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProfileIndex {
    pub profiles: Vec<TunnelProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileImportParams {
    pub conf_text: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub backend: Option<TunnelBackendPreference>,
    #[serde(default)]
    pub transport: Option<TunnelTransportConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileExportParams {
    pub name: String,
    #[serde(default = "default_export_mode")]
    pub mode: String,
}

fn default_export_mode() -> String {
    "full".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileValidateParams {
    pub conf_text: String,
    #[serde(default)]
    pub backend: Option<TunnelBackendPreference>,
    #[serde(default)]
    pub transport: Option<TunnelTransportConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileValidateResult {
    pub valid: bool,
    pub kind: ProfileKind,
    pub issues: Vec<ProfileValidationIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileValidationIssue {
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedBackend {
    pub kind: BackendKind,
    pub fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
}
