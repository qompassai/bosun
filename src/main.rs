//! bosun — MCP server for remote device provisioning (stdio).
//!
//! One provisioning surface for the household fleet: device
//! inventory and diagnostics for Android, Windows, and iOS, with
//! every mutation (register, install, update, reboot) behind a
//! pure decide() gate that requires operator approval, and an
//! honest per-device capability model that refuses what a
//! platform cannot do. iOS runs a real MDM: Stage 0 carries the
//! command model and queue; the check-in endpoint, SCEP, and
//! APNs push land in Stage 1 (see STAGE0.md and the README).
//!
//! Modern era only (2026-07-28) on rmcp: sessions open with
//! `server/discover`; the era guard (see `guard`) refuses a
//! legacy `initialize` at the stdio front door with the typed
//! `-32022` error.
//!
//! Usage: `bosun` (no arguments; unknown arguments are warned
//! about and ignored). The inventory lives at
//! `$BOSUN_HOME/inventory.json`, defaulting to
//! `~/.local/share/bosun/inventory.json`.

#![forbid(unsafe_code)]

mod backend;
mod capability;
mod catalog;
mod gate;
mod guard;
mod mdm;
mod server;
mod store;

use std::process::ExitCode;
use std::sync::Arc;

use rmcp::ServiceExt;
use rmcp::transport::async_rw::AsyncRwTransport;
use tokio::sync::Mutex;

/// Duplex buffer between the era guard and the SDK service.
const DUPLEX_BUFFER_BYTES: usize = 1024 * 1024;

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
    for arg in std::env::args().skip(1) {
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
