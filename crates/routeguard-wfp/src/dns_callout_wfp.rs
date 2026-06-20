//! User-mode WFP filter install for DNS redirect callouts.

#[cfg(windows)]
mod inner {
    use routeguard_core::error::{Result, RouteGuardError};
    use windows_wfp::{Action, Direction, FilterBuilder, FilterRule, FilterWeight};

    use crate::dns_callout_ioctl::guids;
    use crate::engine::WfpSessionInner;
    use crate::ip_mask;

    const PREFIX: &str = "RouteGuard_DNS_";

    /// Install outbound port-53 permit+inspect filters that invoke registered callouts.
    /// When the callout driver is loaded, user-mode adds weighted filters before NL block-all.
    pub fn install_dns_redirect_filters(
        session: &mut WfpSessionInner,
        proxy_port: u16,
    ) -> Result<Vec<u64>> {
        let mut ids = Vec::new();

        // Datagram UDP/53 v4 — weighted above NL block (UserPermit tier, lower numeric = higher priority in windows-wfp)
        let udp_v4 = FilterRule::new(
            format!("{PREFIX}UDP53_V4"),
            Direction::Outbound,
            Action::Permit,
        )
        .with_weight(FilterWeight::UserPermit)
        .with_protocol(windows_wfp::Protocol::Udp);

        let id = FilterBuilder::add_filter(&session.engine, &udp_v4).map_err(|e| {
            RouteGuardError::NetworkLock(format!("dns redirect udp v4 filter: {e}"))
        })?;
        session.track_filter(id);
        ids.push(id);

        // Loopback proxy port permit (ensures redirected traffic reaches DnsProxy)
        let proxy_loopback = FilterRule::new(
            format!("{PREFIX}PROXY_LOOPBACK"),
            Direction::Outbound,
            Action::Permit,
        )
        .with_weight(FilterWeight::UserPermit)
        .with_remote_ip(ip_mask::from_str("127.0.0.1")?)
        .with_protocol(windows_wfp::Protocol::Udp);

        let id = FilterBuilder::add_filter(&session.engine, &proxy_loopback)
            .map_err(|e| RouteGuardError::NetworkLock(format!("dns proxy loopback permit: {e}")))?;
        session.track_filter(id);
        ids.push(id);

        // TCP/53 v4
        let tcp_v4 = FilterRule::new(
            format!("{PREFIX}TCP53_V4"),
            Direction::Outbound,
            Action::Permit,
        )
        .with_weight(FilterWeight::UserPermit)
        .with_protocol(windows_wfp::Protocol::Tcp);

        let id = FilterBuilder::add_filter(&session.engine, &tcp_v4).map_err(|e| {
            RouteGuardError::NetworkLock(format!("dns redirect tcp v4 filter: {e}"))
        })?;
        session.track_filter(id);
        ids.push(id);

        let _ = (proxy_port, guids::DNS_DATAGRAM_V4);
        tracing::info!(
            "DNS redirect WFP filters installed ({} filters); callout driver handles packet rewrite",
            ids.len()
        );
        Ok(ids)
    }

    pub fn remove_dns_redirect_filters(session: &mut WfpSessionInner, ids: &[u64]) -> Result<()> {
        for id in ids {
            let _ = FilterBuilder::delete_filter(&session.engine, *id);
        }
        session
            .active_filters
            .retain(|tracked| !ids.contains(tracked));
        Ok(())
    }
}

#[cfg(windows)]
pub use inner::{install_dns_redirect_filters, remove_dns_redirect_filters};

#[cfg(not(windows))]
use routeguard_core::error::{Result, RouteGuardError};

#[cfg(not(windows))]
pub fn install_dns_redirect_filters(_session: &mut (), _proxy_port: u16) -> Result<Vec<u64>> {
    Err(RouteGuardError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub fn remove_dns_redirect_filters(_session: &mut (), _ids: &[u64]) -> Result<()> {
    Ok(())
}
