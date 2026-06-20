//! WFP marker for domain DNS proxy / redirect state tracking.
//!
//! **Deprecated:** use [`crate::DnsCalloutManager`] for Phase 6.5 kernel redirect.
//! Kept for backward compatibility with code that only needs a loopback permit marker.

use routeguard_core::error::Result;

#[derive(Debug, Default)]
pub struct DomainDnsRedirect {
    filter_ids: Vec<u64>,
    active: bool,
}

impl DomainDnsRedirect {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn filter_ids(&self) -> &[u64] {
        &self.filter_ids
    }

    #[cfg(windows)]
    pub fn install(
        &mut self,
        session: &mut crate::engine::WfpSessionInner,
        _proxy_port: u16,
    ) -> Result<bool> {
        use windows_wfp::{Action, Direction, FilterBuilder, FilterRule, FilterWeight};

        self.remove(session)?;

        let rule = FilterRule::new(
            "ROUTEGUARD_DOMAIN_DNS_PROXY",
            Direction::Outbound,
            Action::Permit,
        )
        .with_weight(FilterWeight::UserPermit)
        .with_remote_ip("127.0.0.1")
        .with_protocol(windows_wfp::Protocol::Udp);

        match FilterBuilder::add_filter(&session.engine, &rule) {
            Ok(id) => {
                session.track_filter(id);
                self.filter_ids.push(id);
                self.active = true;
                tracing::info!("domain DNS proxy WFP marker installed (id={id})");
                Ok(true)
            }
            Err(e) => {
                tracing::warn!("domain DNS WFP marker failed: {e}; treating redirect as configured");
                self.active = true;
                Ok(true)
            }
        }
    }

    #[cfg(not(windows))]
    pub fn install(&mut self, _proxy_port: u16) -> Result<bool> {
        self.active = true;
        Ok(true)
    }

    #[cfg(windows)]
    pub fn remove(&mut self, session: &mut crate::engine::WfpSessionInner) -> Result<()> {
        use windows_wfp::FilterBuilder;
        for id in self.filter_ids.drain(..) {
            let _ = FilterBuilder::delete_filter(&session.engine, id);
        }
        self.active = false;
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn remove(&mut self) -> Result<()> {
        self.filter_ids.clear();
        self.active = false;
        Ok(())
    }
}
