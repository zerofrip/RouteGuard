//! AWG parameter validation.

use crate::params::AwgParams;

const MAX_MAGIC_HEADER_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    pub field: String,
    pub message: String,
}

pub fn validate_awg_params(params: &AwgParams) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    if !params.has_any() {
        return issues;
    }

    if let Some(jc) = params.jc {
        if jc > 0 && (params.jmin.is_none() || params.jmax.is_none()) {
            issues.push(ValidationIssue {
                field: "Jc".into(),
                message: "Jc > 0 requires Jmin and Jmax".into(),
            });
        }
    }

    if let (Some(jmin), Some(jmax)) = (params.jmin, params.jmax) {
        if jmin > jmax {
            issues.push(ValidationIssue {
                field: "Jmin".into(),
                message: "Jmin must be <= Jmax".into(),
            });
        }
    }

    for (name, val) in [
        ("H1", params.h1.as_deref()),
        ("H2", params.h2.as_deref()),
        ("H3", params.h3.as_deref()),
        ("H4", params.h4.as_deref()),
    ] {
        if let Some(spec) = val.filter(|s| !s.is_empty()) {
            if spec.len() > MAX_MAGIC_HEADER_LEN {
                issues.push(ValidationIssue {
                    field: name.into(),
                    message: format!("magic header exceeds {MAX_MAGIC_HEADER_LEN} chars"),
                });
            }
            if let Err(msg) = validate_magic_header_spec(spec) {
                issues.push(ValidationIssue {
                    field: name.into(),
                    message: msg,
                });
            }
        }
    }

    issues
}

fn validate_magic_header_spec(spec: &str) -> Result<(), String> {
    let parts: Vec<&str> = spec.split('-').collect();
    if parts.is_empty() || parts.len() > 2 {
        return Err("magic header must be N or N-M".into());
    }
    let start: u64 = parts[0]
        .parse()
        .map_err(|_| format!("invalid start value in {spec}"))?;
    let end = if parts.len() == 2 {
        parts[1]
            .parse::<u64>()
            .map_err(|_| format!("invalid end value in {spec}"))?
    } else {
        start
    };
    if end < start {
        return Err("magic header range end < start".into());
    }
    if start > u32::MAX as u64 || end > u32::MAX as u64 {
        return Err("magic header values must fit u32".into());
    }
    Ok(())
}

pub fn validate_awg_params_strict(params: &AwgParams) -> Result<(), Vec<ValidationIssue>> {
    let issues = validate_awg_params(params);
    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::AwgParams;

    #[test]
    fn jc_requires_jmin_jmax() {
        let p = AwgParams {
            jc: Some(5),
            ..Default::default()
        };
        let issues = validate_awg_params(&p);
        assert!(issues.iter().any(|i| i.field == "Jc"));
    }

    #[test]
    fn valid_magic_header_range() {
        assert!(validate_magic_header_spec("100-200").is_ok());
        assert!(validate_magic_header_spec("42").is_ok());
        assert!(validate_magic_header_spec("200-100").is_err());
    }
}
