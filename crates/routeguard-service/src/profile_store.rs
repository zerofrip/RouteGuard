//! Tunnel profile vault — `%ProgramData%\RouteGuard\profiles\`.

use std::fs;
use std::path::{Path, PathBuf};

use routeguard_awg::{is_awg_profile, parse_awg_from_conf, validate_awg_params, ValidationIssue};
use routeguard_core::backend::{ProfileKind, TunnelBackendPreference};
use routeguard_core::error::{Result, RouteGuardError};
use routeguard_core::profile::{
    ProfileExportParams, ProfileImportParams, ProfileIndex, ProfileValidateParams,
    ProfileValidateResult, ProfileValidationIssue, TunnelProfile,
};
use routeguard_core::transport::{
    merge_transport_config, transport_hints_from_conf, transport_summary, TransportPreference,
    TunnelTransportConfig,
};
use routeguard_lwo::LwoBackend;
use routeguard_phantun::PhantunBackend;
use routeguard_platform::DirectUdpBackend;
use uuid::Uuid;

const PROFILES_DIR: &str = "profiles";
const INDEX_FILE: &str = "profiles.json";

pub fn profiles_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("ProgramData") {
            return PathBuf::from(p).join("RouteGuard").join(PROFILES_DIR);
        }
    }
    PathBuf::from("/var/lib/routeguard").join(PROFILES_DIR)
}

fn index_path() -> PathBuf {
    profiles_dir().join(INDEX_FILE)
}

fn load_index() -> Result<ProfileIndex> {
    let path = index_path();
    if !path.exists() {
        return Ok(ProfileIndex::default());
    }
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn save_index(index: &ProfileIndex) -> Result<()> {
    let dir = profiles_dir();
    fs::create_dir_all(&dir)?;
    fs::write(index_path(), serde_json::to_string_pretty(index)?)?;
    Ok(())
}

fn profile_conf_path(name: &str) -> PathBuf {
    profiles_dir().join(format!("{name}.conf"))
}

pub fn validate_conf_text(
    conf_text: &str,
    backend: Option<TunnelBackendPreference>,
    transport: Option<&TunnelTransportConfig>,
) -> ProfileValidateResult {
    let kind = if is_awg_profile(conf_text) {
        ProfileKind::Awg
    } else {
        ProfileKind::Standard
    };

    let mut issues: Vec<ProfileValidationIssue> = Vec::new();

    if conf_text.to_ascii_lowercase().contains("privatekey") {
        // minimal sanity
    } else {
        issues.push(ProfileValidationIssue {
            field: "Interface".into(),
            message: "missing PrivateKey".into(),
        });
    }

    let awg = parse_awg_from_conf(conf_text);
    for issue in validate_awg_params(&awg) {
        issues.push(map_issue(issue));
    }

    if matches!(backend, Some(TunnelBackendPreference::WireGuardNt)) && awg.has_any() {
        issues.push(ProfileValidationIssue {
            field: "backend".into(),
            message: "AWG parameters present but backend set to wireguard-nt".into(),
        });
    }

    let hints = transport_hints_from_conf(conf_text);
    let merged = merge_transport_config(&hints, transport, None);
    let transport_backend: &dyn routeguard_core::transport::TransportBackend = match merged.preference {
        TransportPreference::Phantun => &PhantunBackend::new(),
        TransportPreference::Lwo => &LwoBackend::new(),
        _ => &DirectUdpBackend::new(),
    };
    for issue in transport_backend.validate(conf_text, &merged).issues {
        issues.push(ProfileValidationIssue {
            field: issue.field,
            message: issue.message,
        });
    }

    ProfileValidateResult {
        valid: issues.is_empty(),
        kind,
        issues,
    }
}

fn map_issue(i: ValidationIssue) -> ProfileValidationIssue {
    ProfileValidationIssue {
        field: i.field,
        message: i.message,
    }
}

pub fn import_profile(params: ProfileImportParams) -> Result<TunnelProfile> {
    let hints = transport_hints_from_conf(&params.conf_text);
    let merged_transport = merge_transport_config(&hints, params.transport.as_ref(), None);
    let validation = validate_conf_text(
        &params.conf_text,
        params.backend,
        Some(&merged_transport),
    );
    if !validation.valid {
        return Err(RouteGuardError::Config(format!(
            "profile validation failed: {:?}",
            validation.issues
        )));
    }

    let name = params
        .name
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("profile-{}", Uuid::new_v4()));

    fs::create_dir_all(profiles_dir())?;
    let conf_path = profile_conf_path(&name);
    fs::write(&conf_path, &params.conf_text)?;

    let endpoint = extract_endpoint(&params.conf_text);
    let remote_addr = merged_transport
        .lwo
        .as_ref()
        .and_then(|l| l.remote_udp.as_ref())
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
        .or_else(|| {
            merged_transport
                .phantun
                .as_ref()
                .and_then(|p| p.remote_tcp.as_ref())
                .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
        });
    let kind = match merged_transport.preference {
        TransportPreference::Phantun => routeguard_core::transport::TransportKind::Phantun,
        TransportPreference::Lwo => routeguard_core::transport::TransportKind::Lwo,
        _ => {
            let hints = transport_hints_from_conf(&params.conf_text);
            if hints.lwo.is_some() {
                routeguard_core::transport::TransportKind::Lwo
            } else if hints.phantun.is_some() {
                routeguard_core::transport::TransportKind::Phantun
            } else {
                routeguard_core::transport::TransportKind::DirectUdp
            }
        }
    };
    let transport_summary = Some(transport_summary(kind, remote_addr.as_ref()));

    let profile = TunnelProfile {
        id: Uuid::new_v4(),
        name: name.clone(),
        kind: validation.kind,
        backend: params.backend.unwrap_or_default(),
        config_path: conf_path,
        endpoint_summary: endpoint,
        transport: Some(merged_transport),
        transport_summary,
        imported_from: Some("import".into()),
        created_at: chrono_lite_now(),
    };

    let mut index = load_index()?;
    index.profiles.retain(|p| p.name != name);
    index.profiles.push(profile.clone());
    save_index(&index)?;

    Ok(profile)
}

pub fn list_profiles() -> Result<Vec<TunnelProfile>> {
    Ok(load_index()?.profiles)
}

pub fn get_profile(name: &str) -> Result<Option<TunnelProfile>> {
    Ok(load_index()?
        .profiles
        .into_iter()
        .find(|p| p.name == name))
}

pub fn export_profile(params: ProfileExportParams) -> Result<String> {
    let profile = get_profile(&params.name)?
        .ok_or_else(|| RouteGuardError::Config(format!("profile not found: {}", params.name)))?;
    let text = fs::read_to_string(&profile.config_path)?;
    if params.mode == "sanitized" {
        return Ok(sanitize_conf(&text));
    }
    Ok(text)
}

pub fn delete_profile(name: &str) -> Result<()> {
    let mut index = load_index()?;
    if let Some(pos) = index.profiles.iter().position(|p| p.name == name) {
        let profile = index.profiles.remove(pos);
        let _ = fs::remove_file(profile.config_path);
        save_index(&index)?;
    }
    Ok(())
}

pub fn validate_profile(params: ProfileValidateParams) -> ProfileValidateResult {
    let hints = transport_hints_from_conf(&params.conf_text);
    let merged = merge_transport_config(&hints, params.transport.as_ref(), None);
    validate_conf_text(&params.conf_text, params.backend, Some(&merged))
}

fn extract_endpoint(conf: &str) -> Option<String> {
    for line in conf.lines() {
        let line = line.trim();
        if line.to_ascii_lowercase().starts_with("endpoint") {
            if let Some((_, v)) = line.split_once('=') {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn sanitize_conf(text: &str) -> String {
    text.lines()
        .filter(|l| {
            let lower = l.to_ascii_lowercase();
            !lower.starts_with("privatekey") && !lower.starts_with("presharedkey")
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_standard_conf() {
        let conf = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = 1.2.3.4:51820\n";
        let r = validate_conf_text(conf, None, None);
        assert!(r.valid);
        assert_eq!(r.kind, ProfileKind::Standard);
    }

    #[test]
    fn validate_awg_conf_detects_kind() {
        let conf = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nJc = 3\nJmin = 10\nJmax = 50\n";
        let r = validate_conf_text(conf, None, None);
        assert_eq!(r.kind, ProfileKind::Awg);
    }
}
