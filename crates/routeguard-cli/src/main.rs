use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use routeguard_core::ipc::methods;
use routeguard_core::ipc::{ConnectParams, IpcClient, IpcRequest, RoutingTestParams};
use routeguard_core::RouteGuardError;
use serde_json::json;

#[derive(Parser, Debug)]
#[command(name = "routeguard-cli", version, about = "RouteGuard VPN CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Connect to a tunnel
    Connect {
        name: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Disconnect active tunnel
    Disconnect,
    /// Show tunnel and network lock status
    Status,
    /// Reload routing rules from config
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Network lock (kill switch) control
    NetworkLock {
        #[command(subcommand)]
        action: NetworkLockAction,
    },
    /// Test routing decision for a flow
    Test {
        #[arg(long)]
        ip: String,
        #[arg(long)]
        app: Option<PathBuf>,
        #[arg(long)]
        domain: Option<String>,
    },
    /// Show service config
    Config,
}

#[derive(Subcommand, Debug)]
enum RulesAction {
    Reload,
    List,
    /// Add an application split-tunnel rule
    AddApp {
        path: PathBuf,
        #[arg(long, value_parser = ["exclude", "include"])]
        mode: String,
        #[arg(long)]
        priority: Option<u16>,
    },
    /// Remove an application split-tunnel rule
    RemoveApp {
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum NetworkLockAction {
    Enable,
    Disable,
    Status,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            if matches!(e, RouteGuardError::ServiceNotRunning) {
                ExitCode::from(2)
            } else {
                ExitCode::from(1)
            }
        }
    }
}

async fn run(cli: Cli) -> routeguard_core::Result<()> {
    match cli.command {
        Commands::Connect { name, config } => {
            let resp = rpc(
                methods::TUNNEL_CONNECT,
                json!(ConnectParams {
                    name,
                    config_path: config,
                }),
            )
            .await?;
            print_result(&resp);
        }
        Commands::Disconnect => {
            let resp = rpc(methods::TUNNEL_DISCONNECT, json!({})).await?;
            print_result(&resp);
        }
        Commands::Status => {
            let resp = rpc(methods::TUNNEL_STATUS, json!({})).await?;
            print_result(&resp);
        }
        Commands::Rules { action } => match action {
            RulesAction::Reload => {
                let resp = rpc(methods::ROUTING_RELOAD, json!({})).await?;
                print_result(&resp);
            }
            RulesAction::List => {
                let resp = rpc(methods::ROUTING_GET, json!({})).await?;
                print_result(&resp);
            }
            RulesAction::AddApp {
                path,
                mode,
                priority,
            } => {
                let resp = rpc(
                    methods::ROUTING_ADD_APP,
                    json!({
                        "path": path,
                        "mode": mode,
                        "priority": priority,
                    }),
                )
                .await?;
                print_result(&resp);
            }
            RulesAction::RemoveApp { path } => {
                let resp = rpc(
                    methods::ROUTING_REMOVE_APP,
                    json!({ "path": path }),
                )
                .await?;
                print_result(&resp);
            }
        },
        Commands::NetworkLock { action } => match action {
            NetworkLockAction::Enable => {
                let resp = rpc(methods::NETWORK_LOCK_ENABLE, json!({})).await?;
                print_result(&resp);
            }
            NetworkLockAction::Disable => {
                let resp = rpc(methods::NETWORK_LOCK_DISABLE, json!({})).await?;
                print_result(&resp);
            }
            NetworkLockAction::Status => {
                let resp = rpc(methods::NETWORK_LOCK_STATUS, json!({})).await?;
                print_result(&resp);
            }
        },
        Commands::Test { ip, app, domain } => {
            let resp = rpc(
                methods::ROUTING_TEST,
                json!(RoutingTestParams {
                    app_path: app,
                    remote_ip: ip,
                    domain,
                }),
            )
            .await?;
            print_result(&resp);
        }
        Commands::Config => {
            let resp = rpc(methods::CONFIG_GET, json!({})).await?;
            print_result(&resp);
        }
    }
    Ok(())
}

async fn rpc(
    method: &str,
    params: serde_json::Value,
) -> routeguard_core::Result<serde_json::Value> {
    static ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let req = IpcRequest::new(id, method, params);
    let resp = IpcClient::call(req).await.map_err(|e| match e {
        RouteGuardError::Ipc(msg) if msg.contains("pipe connect") => {
            RouteGuardError::ServiceNotRunning
        }
        other => other,
    })?;
    if let Some(err) = resp.error {
        return Err(RouteGuardError::Ipc(format!(
            "{} ({})",
            err.message, err.code
        )));
    }
    Ok(resp.result.unwrap_or(json!({})))
}

fn print_result(v: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
    );
}
