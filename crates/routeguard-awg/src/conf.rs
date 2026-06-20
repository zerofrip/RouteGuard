//! Parse and build AWG keys in WireGuard `.conf` text.

use crate::params::AwgParams;

/// Parse AWG interface keys from full `.conf` text.
pub fn parse_awg_from_conf(text: &str) -> AwgParams {
    let mut params = AwgParams::default();
    let mut in_interface = false;

    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_interface = line.eq_ignore_ascii_case("[Interface]");
            continue;
        }
        if !in_interface {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        match key.as_str() {
            "jc" => params.jc = val.parse().ok(),
            "jmin" => params.jmin = val.parse().ok(),
            "jmax" => params.jmax = val.parse().ok(),
            "s1" => params.s1 = val.parse().ok(),
            "s2" => params.s2 = val.parse().ok(),
            "h1" => params.h1 = Some(val.to_string()),
            "h2" => params.h2 = Some(val.to_string()),
            "h3" => params.h3 = Some(val.to_string()),
            "h4" => params.h4 = Some(val.to_string()),
            _ => {}
        }
    }

    params
}

/// Append AWG interface lines to conf builder output.
pub fn append_awg_lines(out: &mut String, params: &AwgParams) {
    if let Some(v) = params.jc {
        out.push_str(&format!("Jc = {v}\n"));
    }
    if let Some(v) = params.jmin {
        out.push_str(&format!("Jmin = {v}\n"));
    }
    if let Some(v) = params.jmax {
        out.push_str(&format!("Jmax = {v}\n"));
    }
    if let Some(v) = params.s1 {
        out.push_str(&format!("S1 = {v}\n"));
    }
    if let Some(v) = params.s2 {
        out.push_str(&format!("S2 = {v}\n"));
    }
    if let Some(v) = params.h1.as_deref().filter(|s| !s.is_empty()) {
        out.push_str(&format!("H1 = {v}\n"));
    }
    if let Some(v) = params.h2.as_deref().filter(|s| !s.is_empty()) {
        out.push_str(&format!("H2 = {v}\n"));
    }
    if let Some(v) = params.h3.as_deref().filter(|s| !s.is_empty()) {
        out.push_str(&format!("H3 = {v}\n"));
    }
    if let Some(v) = params.h4.as_deref().filter(|s| !s.is_empty()) {
        out.push_str(&format!("H4 = {v}\n"));
    }
}

pub fn is_awg_profile(text: &str) -> bool {
    parse_awg_from_conf(text).has_any()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_awg_keys() {
        let conf = r#"
[Interface]
PrivateKey = x
Jc = 4
Jmin = 50
Jmax = 1000
H1 = 1-100

[Peer]
PublicKey = y
"#;
        let p = parse_awg_from_conf(conf);
        assert_eq!(p.jc, Some(4));
        assert_eq!(p.jmin, Some(50));
        assert_eq!(p.h1.as_deref(), Some("1-100"));
        assert!(is_awg_profile(conf));
    }

    #[test]
    fn standard_wg_not_awg() {
        let conf = "[Interface]\nPrivateKey = x\n";
        assert!(!is_awg_profile(conf));
    }
}
