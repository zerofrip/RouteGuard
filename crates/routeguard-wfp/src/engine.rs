#[cfg(windows)]
pub mod inner {
    use routeguard_core::error::{Result, RouteGuardError};
    use windows_wfp::{initialize_wfp, WfpEngine};

    pub struct WfpSessionInner {
        pub engine: WfpEngine,
        pub active_filters: Vec<u64>,
    }

    impl WfpSessionInner {
        pub fn open() -> Result<Self> {
            let engine = WfpEngine::new()
                .map_err(|e| RouteGuardError::NetworkLock(format!("WfpEngine::new: {e}")))?;
            initialize_wfp(&engine)
                .map_err(|e| RouteGuardError::NetworkLock(format!("initialize_wfp: {e}")))?;
            Ok(Self {
                engine,
                active_filters: Vec::new(),
            })
        }

        pub fn track_filter(&mut self, id: u64) {
            self.active_filters.push(id);
        }

        pub fn clear_filters(&mut self) -> Result<()> {
            use windows_wfp::FilterBuilder;
            for id in self.active_filters.drain(..) {
                let _ = FilterBuilder::delete_filter(&self.engine, id);
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
pub use inner::WfpSessionInner;

#[cfg(windows)]
pub struct WfpSession {
    inner: WfpSessionInner,
    network_lock: crate::NetworkLock,
}

#[cfg(windows)]
impl WfpSession {
    pub fn open() -> routeguard_core::Result<Self> {
        let inner = WfpSessionInner::open()?;
        let state = crate::persistent::load_state().unwrap_or_default();
        let mut network_lock = crate::NetworkLock::new();
        network_lock.restore_state(state);
        Ok(Self {
            inner,
            network_lock,
        })
    }

    pub fn apply_policy(
        &mut self,
        policy: &routeguard_core::policy::PolicySnapshot,
    ) -> routeguard_core::Result<()> {
        let previous = policy.wfp_filter_ids.clone();
        let ids = crate::split_tunnel::apply_split_tunnel(&mut self.inner, policy, &previous)?;
        let mut updated = policy.clone();
        updated.wfp_filter_ids = ids;
        crate::persistent::save_session_snapshot(&updated)?;
        Ok(())
    }

    pub fn apply_split_policy(
        &mut self,
        policy: &routeguard_core::policy::PolicySnapshot,
        previous_ids: &[u64],
    ) -> routeguard_core::Result<Vec<u64>> {
        crate::split_tunnel::apply_split_tunnel(&mut self.inner, policy, previous_ids)
    }

    pub fn enable_network_lock(
        &mut self,
        policy: &crate::NetworkLockPolicy,
    ) -> routeguard_core::Result<()> {
        self.network_lock.enable(&mut self.inner, policy)
    }

    pub fn disable_network_lock(&mut self) -> routeguard_core::Result<()> {
        self.network_lock.disable(&mut self.inner)
    }

    pub fn network_lock_enabled(&self) -> bool {
        self.network_lock.is_enabled()
    }

    pub fn inner_mut(&mut self) -> &mut WfpSessionInner {
        &mut self.inner
    }
}
