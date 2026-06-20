use std::path::{Path, PathBuf};

use routeguard_core::config::{AppRule, RuleMode};

/// Normalized application rule set.
#[derive(Debug, Clone, Default)]
pub struct AppRuleSet {
    pub excludes: Vec<AppRuleEntry>,
    pub includes: Vec<AppRuleEntry>,
}

#[derive(Debug, Clone)]
pub struct AppRuleEntry {
    pub priority: u16,
    pub path: PathBuf,
    pub normalized: String,
}

impl AppRuleSet {
    pub fn from_rules(rules: &[AppRule]) -> Self {
        let mut set = Self::default();
        for rule in rules {
            let entry = AppRuleEntry {
                priority: rule.priority,
                path: rule.path.clone(),
                normalized: normalize_path(&rule.path),
            };
            match rule.mode {
                RuleMode::Exclude => set.excludes.push(entry),
                RuleMode::Include => set.includes.push(entry),
            }
        }
        set.excludes.sort_by_key(|r| r.priority);
        set.includes.sort_by_key(|r| r.priority);
        set
    }

    pub fn match_path(
        &self,
        app_path: &Path,
        mode: routeguard_core::config::RoutingMode,
    ) -> Option<(RuleMode, u16)> {
        let normalized = normalize_path(app_path);
        match mode {
            routeguard_core::config::RoutingMode::FullTunnel => {
                for rule in &self.excludes {
                    if path_matches(&rule.normalized, &normalized) {
                        return Some((RuleMode::Exclude, rule.priority));
                    }
                }
            }
            routeguard_core::config::RoutingMode::SplitInclude => {
                for rule in &self.includes {
                    if path_matches(&rule.normalized, &normalized) {
                        return Some((RuleMode::Include, rule.priority));
                    }
                }
            }
        }
        None
    }
}

pub fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").to_lowercase()
}

fn path_matches(rule: &str, candidate: &str) -> bool {
    if rule.contains('*') {
        glob_match(rule, candidate)
    } else {
        candidate == rule || candidate.ends_with(rule)
    }
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.is_empty() {
        return true;
    }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            if !text[pos..].ends_with(part) {
                return false;
            }
        } else if let Some(idx) = text[pos..].find(part) {
            pos += idx + part.len();
        } else {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_chrome() {
        assert!(glob_match(
            r"c:\program files*\chrome.exe",
            r"c:\program files\google\chrome\application\chrome.exe"
        ));
    }
}
