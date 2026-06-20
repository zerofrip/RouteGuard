//! Windows Filtering Platform — network lock, app filters, policy compiler.

pub mod app_filter;
pub mod app_id;
pub mod dns_callout;
pub mod dns_callout_ioctl;
pub mod dns_callout_wfp;
pub mod domain_redirect;
pub mod engine;
pub mod filters;
pub mod ip_mask;
pub mod network_lock;
pub mod persistent;
pub mod policy;
pub mod recovery;
pub mod split_tunnel;

pub use dns_callout::{probe_callout_driver, DnsCalloutManager};
pub use dns_callout_ioctl::RgDnsRedirectStats;
pub use domain_redirect::DomainDnsRedirect;
pub use network_lock::{NetworkLock, NetworkLockPolicy, NetworkLockState};
pub use policy::WfpPolicyCompiler;
pub use recovery::cleanup_stale;
pub use split_tunnel::{apply_split_tunnel, remove_split_filters};

#[cfg(windows)]
pub use engine::WfpSession;

#[cfg(not(windows))]
mod stub {
    use routeguard_core::error::{Result, RouteGuardError};
    use routeguard_core::policy::PolicySnapshot;

    use crate::network_lock::NetworkLockPolicy;

    pub struct WfpSession;

    impl WfpSession {
        pub fn open() -> Result<Self> {
            Err(RouteGuardError::UnsupportedPlatform)
        }

        pub fn apply_policy(&mut self, _policy: &PolicySnapshot) -> Result<()> {
            Err(RouteGuardError::UnsupportedPlatform)
        }

        pub fn apply_split_policy(
            &mut self,
            _policy: &PolicySnapshot,
            _previous_ids: &[u64],
        ) -> Result<Vec<u64>> {
            Err(RouteGuardError::UnsupportedPlatform)
        }

        pub fn enable_network_lock(&mut self, _policy: &NetworkLockPolicy) -> Result<()> {
            Err(RouteGuardError::UnsupportedPlatform)
        }

        pub fn disable_network_lock(&mut self) -> Result<()> {
            Err(RouteGuardError::UnsupportedPlatform)
        }

        pub fn network_lock_enabled(&self) -> bool {
            false
        }
    }
}

#[cfg(not(windows))]
pub use stub::WfpSession;
