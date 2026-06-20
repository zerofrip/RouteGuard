//! Mode-aware application split tunnel WFP filters.

#[cfg(windows)]
mod imp {
    use routeguard_core::config::RoutingMode;
    use routeguard_core::error::{Result, RouteGuardError};
    use routeguard_core::policy::PolicySnapshot;
    use windows_wfp::{Action, Direction, FilterBuilder, FilterRule, FilterWeight};

    use crate::engine::WfpSessionInner;
    use crate::ip_mask;

    const PREFIX: &str = "RouteGuard_SPLIT_";

    pub fn remove_split_filters(session: &mut WfpSessionInner, ids: &[u64]) -> Result<()> {
        for id in ids {
            let _ = FilterBuilder::delete_filter(&session.engine, *id);
        }
        session.active_filters.retain(|id| !ids.contains(id));
        Ok(())
    }

    pub fn apply_split_tunnel(
        session: &mut WfpSessionInner,
        policy: &PolicySnapshot,
        previous_ids: &[u64],
    ) -> Result<Vec<u64>> {
        remove_split_filters(session, previous_ids)?;

        let mut ids = Vec::new();

        if policy.tunnel_if_index.is_none() {
            return Ok(ids);
        }

        match policy.routing_mode {
            RoutingMode::FullTunnel => {
                ids.extend(install_full_tunnel_exclude(session, policy)?);
            }
            RoutingMode::SplitInclude => {
                ids.extend(install_split_include(session, policy)?);
            }
        }

        for id in &ids {
            session.track_filter(*id);
        }

        Ok(ids)
    }

    fn install_full_tunnel_exclude(
        session: &mut WfpSessionInner,
        policy: &PolicySnapshot,
    ) -> Result<Vec<u64>> {
        let mut ids = Vec::new();

        for (i, app) in policy.bypass_apps.iter().enumerate() {
            let permit = FilterRule::new(
                format!("{PREFIX}PERMIT_EXCL_{i}"),
                Direction::Outbound,
                Action::Permit,
            )
            .with_weight(FilterWeight::UserPermit)
            .with_app_path(&app.path);
            ids.push(add_filter(session, permit)?);

            let block_tun = FilterRule::new(
                format!("{PREFIX}BLOCK_TUN_EXCL_{i}"),
                Direction::Outbound,
                Action::Block,
            )
            .with_weight(FilterWeight::UserBlock)
            .with_app_path(&app.path);
            ids.push(add_filter(session, block_tun)?);
        }

        if policy.tunnel_if_index.is_some() && !policy.bypass_apps.is_empty() {
            let tun_permit = FilterRule::new(
                format!("{PREFIX}PERMIT_TUN"),
                Direction::Outbound,
                Action::Permit,
            )
            .with_weight(FilterWeight::UserPermit);
            ids.push(add_filter(session, tun_permit)?);
        }

        for (i, cidr) in policy.block_cidrs.iter().enumerate() {
            let rule = FilterRule::new(
                format!("{PREFIX}IP_BLOCK_{i}"),
                Direction::Outbound,
                Action::Block,
            )
            .with_weight(FilterWeight::UserBlock)
            .with_remote_ip(ip_mask::from_str(cidr)?);
            ids.push(add_filter(session, rule)?);
        }

        Ok(ids)
    }

    fn install_split_include(
        session: &mut WfpSessionInner,
        policy: &PolicySnapshot,
    ) -> Result<Vec<u64>> {
        let mut ids = Vec::new();

        for (i, app) in policy.tunnel_apps.iter().enumerate() {
            let permit = FilterRule::new(
                format!("{PREFIX}PERMIT_INC_{i}"),
                Direction::Outbound,
                Action::Permit,
            )
            .with_weight(FilterWeight::UserPermit)
            .with_app_path(&app.path);
            ids.push(add_filter(session, permit)?);

            let block = FilterRule::new(
                format!("{PREFIX}BLOCK_PHYS_INC_{i}"),
                Direction::Outbound,
                Action::Block,
            )
            .with_weight(FilterWeight::UserBlock)
            .with_app_path(&app.path);
            ids.push(add_filter(session, block)?);
        }

        Ok(ids)
    }

    fn add_filter(session: &mut WfpSessionInner, rule: FilterRule) -> Result<u64> {
        FilterBuilder::add_filter(&session.engine, &rule)
            .map_err(|e| RouteGuardError::Routing(format!("split filter: {e}")))
    }

    #[cfg(test)]
    pub fn diff_filter_ids(previous: &[u64], current: &[u64]) -> (Vec<u64>, Vec<u64>) {
        let removed: Vec<u64> = previous
            .iter()
            .copied()
            .filter(|id| !current.contains(id))
            .collect();
        let added: Vec<u64> = current
            .iter()
            .copied()
            .filter(|id| !previous.contains(id))
            .collect();
        (removed, added)
    }
}

#[cfg(windows)]
pub use imp::{apply_split_tunnel, remove_split_filters};

#[cfg(not(windows))]
pub fn apply_split_tunnel(
    _session: &mut (),
    _policy: &routeguard_core::policy::PolicySnapshot,
    _previous_ids: &[u64],
) -> routeguard_core::Result<Vec<u64>> {
    Ok(Vec::new())
}

#[cfg(not(windows))]
pub fn remove_split_filters(_ids: &[u64]) -> routeguard_core::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn diff_filter_ids_logic() {
        #[cfg(windows)]
        {
            let (removed, added) = super::imp::diff_filter_ids(&[1, 2, 3], &[2, 3, 4]);
            assert_eq!(removed, vec![1]);
            assert_eq!(added, vec![4]);
        }
    }
}
