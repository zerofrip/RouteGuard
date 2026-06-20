#[cfg(windows)]
use routeguard_core::error::Result;

#[cfg(windows)]
pub fn cleanup_stale() -> Result<usize> {
    use crate::engine::WfpSessionInner;
    use crate::persistent;

    let mut removed = 0usize;

    if let Ok(mut session) = WfpSessionInner::open() {
        removed = session.active_filters.len();
        session.clear_filters()?;
    }

    if let Ok(Some(dns_state)) = persistent::load_dns_redirect_state() {
        if let Ok(mut session) = WfpSessionInner::open() {
            use windows_wfp::FilterBuilder;
            for id in dns_state.wfp_filter_ids {
                let _ = FilterBuilder::delete_filter(&session.engine, id);
            }
        }
        let _ = persistent::save_dns_redirect_state(&persistent::DnsRedirectState::default());
    }

    let state = crate::network_lock::NetworkLockState::default();
    persistent::save_state(&state)?;

    tracing::info!("WFP recovery: cleared {removed} tracked filters");
    Ok(removed)
}

#[cfg(not(windows))]
pub fn cleanup_stale() -> routeguard_core::Result<usize> {
    Ok(0)
}
