//! bosun — MCP server for remote device provisioning (stdio).
//!
//! One provisioning surface for the household fleet: device
//! inventory and diagnostics for Android, Windows, and iOS, with
//! every mutation (register, install, update, reboot) behind a
//! pure decide() gate that requires operator approval, and an
//! honest per-device capability model that refuses what a
//! platform cannot do. iOS runs a real MDM: Stage 1 adds the
//! check-in/command server, the fenced local-CA SCEP step, APNs
//! push, and the verified approval channel (see STAGE1.md).
//!
//! Modern era only (2026-07-28) on rmcp: sessions open with
//! `server/discover`; the era guard (see `guard`) refuses a
//! legacy `initialize` at the stdio front door with the typed
//! `-32022` error.
//!
//! Usage:
//! - `bosun` — the MCP server (unknown arguments are warned
//!   about and ignored). The inventory lives at
//!   `$BOSUN_HOME/inventory.json`, defaulting to
//!   `~/.local/share/bosun/inventory.json`.
//! - `bosun mdm-serve` — the MDM HTTPS server (check-in,
//!   command channel, SCEP, profile download).
//! - `bosun ca-init` — create the local SCEP CA under the home.
//! - `bosun approve --action A --by NAME [--device ID]
//!   [--ttl SECONDS]` — mint an approval-channel token on
//!   stdout (creating the approval key on first use).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use bosun::approval::{self, ApprovalKey, DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS};
use bosun::config::MdmConfig;
use bosun::gate::Action;
use bosun::mdmhttp;
use bosun::scep::LocalCa;
use bosun::{guard, server, store};
use rmcp::ServiceExt;
use rmcp::transport::async_rw::AsyncRwTransport;
use tokio::sync::Mutex;

/// Duplex buffer between the era guard and the SDK service.
const DUPLEX_BUFFER_BYTES: usize = 1024 * 1024;

fn home_from_env() -> Result<PathBuf, String> {
    let path = store::Store::path_from_env().map_err(|e| format!("{}: {}", e.code, e.message))?;
    Ok(path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".")))
}

fn mdm_serve_cmd() -> ExitCode {
    let home = match home_from_env() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("bosun: {e}");
            return ExitCode::FAILURE;
        }
    };
    let config = match MdmConfig::from_env(&home) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bosun: {}: {}", e.code, e.message);
            return ExitCode::FAILURE;
        }
    };
    match mdmhttp::serve(mdmhttp::Context::new(home, config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bosun mdm-serve: {}: {}", e.code, e.message);
            ExitCode::FAILURE
        }
    }
}

fn ca_init_cmd() -> ExitCode {
    let home = match home_from_env() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("bosun: {e}");
            return ExitCode::FAILURE;
        }
    };
    match LocalCa::new(&home).init() {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("bosun ca-init: {}: {}", e.code, e.message);
            ExitCode::FAILURE
        }
    }
}

fn approve_cmd(args: &[String]) -> ExitCode {
    let mut action: Option<String> = None;
    let mut device: Option<String> = None;
    let mut by: Option<String> = None;
    let mut ttl: u64 = DEFAULT_TTL_SECONDS;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--action" => action = it.next().cloned(),
            "--device" => device = it.next().cloned(),
            "--by" => by = it.next().cloned(),
            "--ttl" => {
                ttl = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(DEFAULT_TTL_SECONDS)
            }
            other => {
                eprintln!("bosun approve: unknown flag {other}");
                return ExitCode::FAILURE;
            }
        }
    }
    let (Some(action), Some(by)) = (action, by) else {
        eprintln!(
            "usage: bosun approve --action <action> --by <name> [--device <id>] [--ttl <seconds>]"
        );
        return ExitCode::FAILURE;
    };
    if Action::parse(&action).is_none() {
        eprintln!("bosun approve: unknown action {action:?}");
        return ExitCode::FAILURE;
    }
    if by.trim().is_empty() {
        eprintln!("bosun approve: --by must name the approver");
        return ExitCode::FAILURE;
    }
    if ttl == 0 || ttl > MAX_TTL_SECONDS {
        eprintln!("bosun approve: --ttl must be 1..={MAX_TTL_SECONDS} seconds");
        return ExitCode::FAILURE;
    }
    let home = match home_from_env() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("bosun: {e}");
            return ExitCode::FAILURE;
        }
    };
    let config = match MdmConfig::from_env(&home) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bosun: {}: {}", e.code, e.message);
            return ExitCode::FAILURE;
        }
    };
    let key = match ApprovalKey::load(&config.approval_key_file) {
        Ok(Some(k)) => k,
        Ok(None) => {
            eprintln!(
                "bosun approve: no approval key at {}; creating one (0600)",
                config.approval_key_file.display()
            );
            match ApprovalKey::create(&config.approval_key_file) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("bosun approve: {}: {}", e.code, e.message);
                    return ExitCode::FAILURE;
                }
            }
        }
        Err(e) => {
            eprintln!("bosun approve: {}: {}", e.code, e.message);
            return ExitCode::FAILURE;
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires = now + ttl;
    let token = approval::mint(&key, &action, device.as_deref(), &by, expires);
    eprintln!(
        "bosun approve: token for action={action} device={} by={by} expires={expires}",
        device.as_deref().unwrap_or("-")
    );
    println!("{token}");
    ExitCode::SUCCESS
}

async fn run() -> std::io::Result<()> {
    let store_path = store::Store::path_from_env()
        .map_err(|e| std::io::Error::other(format!("{}: {}", e.code, e.message)))?;
    let store = store::Store::load(store_path)
        .map_err(|e| std::io::Error::other(format!("{}: {}", e.code, e.message)))?;

    let (client_side, server_side) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);
    let (server_read, server_write) = tokio::io::split(server_side);
    let (client_read, client_write) = tokio::io::split(client_side);
    let stdout: guard::SharedStdout = Arc::new(Mutex::new(tokio::io::stdout()));

    let handler = server::BosunServer::new(store);
    let serve = tokio::spawn(async move {
        let transport = AsyncRwTransport::new_server(server_read, server_write);
        match handler.serve(transport).await {
            Ok(running) => running
                .waiting()
                .await
                .map(|_| ())
                .map_err(|e| std::io::Error::other(e.to_string())),
            // The client closed before selecting a lifecycle (a
            // probe, a spawn check): bare EOF is a clean end.
            Err(rmcp::service::ServerInitializeError::ConnectionClosed(_)) => Ok(()),
            Err(e) => Err(std::io::Error::other(e.to_string())),
        }
    });
    let mut pump = tokio::spawn(guard::pump(client_read, Arc::clone(&stdout)));

    let guard_result = guard::run(tokio::io::stdin(), client_write, stdout).await;
    let serve_result = match serve.await {
        Ok(result) => result,
        Err(e) => Err(std::io::Error::other(e.to_string())),
    };
    if tokio::time::timeout(std::time::Duration::from_secs(2), &mut pump)
        .await
        .is_err()
    {
        pump.abort();
    }
    guard_result.and(serve_result)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("mdm-serve") => return mdm_serve_cmd(),
        Some("ca-init") => return ca_init_cmd(),
        Some("approve") => return approve_cmd(&args[1..]),
        _ => {}
    }
    for arg in &args {
        eprintln!("bosun: ignoring unknown arg {arg}");
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("bosun: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bosun: serve loop ended: {e}");
            ExitCode::FAILURE
        }
    }
}
