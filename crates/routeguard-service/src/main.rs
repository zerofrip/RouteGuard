#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        unused_imports,
        unused_variables,
        clippy::too_many_arguments,
        clippy::io_other_error
    )
)]
#![cfg_attr(
    windows,
    allow(
        dead_code,
        unused_imports,
        unused_variables,
        clippy::too_many_arguments,
        clippy::io_other_error
    )
)]

mod backend_selector;
mod connect_session;
mod domain_routing;
mod event_bridge;
mod handler;
mod observability;
mod profile_store;
mod service;
mod transport_health;
mod transport_selector;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use routeguard_core::config::AppConfig;
use routeguard_platform::DnsInterceptor;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "routeguard-service", about = "RouteGuard VPN service")]
struct Args {
    /// Run in foreground (console) instead of Windows Service mode.
    #[arg(long)]
    console: bool,

    /// Run as Windows SCM service (used when registered via installer).
    #[arg(long, hide = true)]
    service: bool,

    /// Path to config.toml
    #[arg(long, default_value = "")]
    config: String,
}

fn default_config_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("ProgramData") {
            return PathBuf::from(p).join("RouteGuard").join("config.toml");
        }
    }
    PathBuf::from("config.toml")
}

#[tokio::main]
async fn main() -> routeguard_core::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("routeguard=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    let config_path = if args.config.is_empty() {
        default_config_path()
    } else {
        PathBuf::from(&args.config)
    };

    let config = load_or_create_config(&config_path).await?;
    let ctx = Arc::new(handler::ServiceContext::new(config_path, config).await?);
    transport_health::spawn_transport_health_monitor(ctx.clone());
    observability::spawn_stats_publisher(ctx.clone());
    observability::spawn_history_persist(ctx.clone());

    #[cfg(windows)]
    if !args.console {
        return service::run_as_service(ctx);
    }

    run_console(ctx).await
}

async fn load_or_create_config(path: &PathBuf) -> routeguard_core::Result<AppConfig> {
    if path.exists() {
        let data = tokio::fs::read_to_string(path).await?;
        AppConfig::from_toml(&data)
    } else {
        let cfg = AppConfig::default();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(path, cfg.to_toml()?).await?;
        Ok(cfg)
    }
}

async fn run_console(ctx: Arc<handler::ServiceContext>) -> routeguard_core::Result<()> {
    tracing::info!("RouteGuard service running in console mode");
    tracing::info!("DNS proxy at {}", ctx.dns.listen_addr());

    #[cfg(windows)]
    {
        let _ = routeguard_wfp::cleanup_stale();
        let handler = ctx.clone();
        let ipc_task = tokio::spawn(async move {
            let server = routeguard_core::ipc::server::PipeServer::new(handler);
            if let Err(e) = server.run().await {
                tracing::error!("IPC server error: {e}");
            }
        });
        tokio::signal::ctrl_c().await.ok();
        ipc_task.abort();
    }

    #[cfg(not(windows))]
    {
        tracing::info!("IPC server requires Windows named pipes; idle until Ctrl+C");
        tokio::signal::ctrl_c().await.ok();
    }

    Ok(())
}
