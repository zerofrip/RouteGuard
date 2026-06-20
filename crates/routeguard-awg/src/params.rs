//! AmneziaWG interface obfuscation parameters (Jc/Jmin/Jmax/S1/S2/H1–H4).

use serde::{Deserialize, Serialize};

/// AWG `[Interface]` obfuscation fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AwgParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jc: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jmin: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jmax: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s1: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s2: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h4: Option<String>,
}

impl AwgParams {
    pub fn has_any(&self) -> bool {
        self.jc.is_some()
            || self.jmin.is_some()
            || self.jmax.is_some()
            || self.s1.is_some()
            || self.s2.is_some()
            || self.h1.as_ref().is_some_and(|s| !s.is_empty())
            || self.h2.as_ref().is_some_and(|s| !s.is_empty())
            || self.h3.as_ref().is_some_and(|s| !s.is_empty())
            || self.h4.as_ref().is_some_and(|s| !s.is_empty())
    }

    pub fn summary(&self) -> AwgParamsSummary {
        AwgParamsSummary {
            jc: self.jc,
            has_magic_headers: [
                self.h1.as_deref(),
                self.h2.as_deref(),
                self.h3.as_deref(),
                self.h4.as_deref(),
            ]
            .iter()
            .any(|h| h.is_some_and(|s| !s.is_empty())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwgParamsSummary {
    pub jc: Option<u16>,
    pub has_magic_headers: bool,
}
