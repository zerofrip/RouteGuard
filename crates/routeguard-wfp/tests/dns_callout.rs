//! DNS callout manager tests (Linux-safe stubs + Windows-only integration hooks).

use routeguard_wfp::dns_callout_ioctl::{
    config_size, stats_size, RgDnsRedirectConfig, RG_DNS_CONFIG_VERSION,
};
use routeguard_wfp::{probe_callout_driver, DnsCalloutManager};

#[test]
fn manager_defaults_without_driver() {
    let mgr = DnsCalloutManager::new();
    assert!(!mgr.kernel_active());
    #[cfg(not(windows))]
    assert!(!mgr.driver_present());
}

#[test]
fn config_roundtrip_fields() {
    let cfg = RgDnsRedirectConfig::loopback_v4(5353, true, &[42, 99]);
    let version = cfg.version;
    let count = cfg.excluded_pid_count;
    let pid0 = cfg.excluded_pids[0];
    let pid1 = cfg.excluded_pids[1];
    assert_eq!(version, RG_DNS_CONFIG_VERSION);
    assert_eq!(count, 2);
    assert_eq!(pid0, 42);
    assert_eq!(pid1, 99);
    assert!(config_size() >= 64);
    assert!(stats_size() >= 64);
}

#[test]
fn probe_returns_false_off_windows_or_without_driver() {
    #[cfg(not(windows))]
    assert!(!probe_callout_driver());
    #[cfg(windows)]
    {
        // Driver may or may not be installed in dev VMs.
        let _ = probe_callout_driver();
    }
}

/// Manual / CI-Windows: requires routeguard-callout.sys loaded.
#[test]
#[cfg(windows)]
#[ignore = "requires routeguard-callout.sys installed and elevated"]
fn integration_driver_ioctl_smoke() {
    let mut mgr = DnsCalloutManager::new();
    if !mgr.probe_driver() {
        eprintln!("skip: callout driver not present");
        return;
    }
    let stats = mgr.get_stats().expect("IOCTL_RG_DNS_GET_STATS");
    let redirected_v4 = stats.redirected_v4;
    eprintln!("redirected_v4={}", redirected_v4);
}
