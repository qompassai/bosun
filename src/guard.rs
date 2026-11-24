//! The era guard: bosun speaks the MCP modern era only
//! (2026-07-28). The guard owns the stdio front door; the rmcp
//! service sits behind an in-process duplex and never sees a
//! legacy handshake.
//!
//! - `server/discover` and every modern-era request/notification
//!   is forwarded to the service untouched.
//! - `initialize` (any version) is answered here with the typed
//!   `-32022` unsupported-version error naming the supported era,
//!   and is never forwarded: there is no legacy session to open.
//! - Malformed lines are forwarded; the service's own parser is
//!   the authority on protocol errors (Rule 6: the guard does not
//!   invent a second error dialect).
//!
//! Known simplification, recorded in STAGE0.md: unlike meister's
//! guard, this one carries no cross-stream ordering barrier —
//! refusals and service responses share the stdout mutex but are
//! not sequenced against each other. A legacy client sends
//! `initialize` before anything else, so the interleave is not
//! reachable in the refusal path's real use; the barrier is the
//! Stage 1 hardening if a client ever proves otherwise.

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

/// The MCP unsupported-protocol-version error code.
const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// The one era this server speaks.
pub const SUPPORTED_ERA: &str = "2026-07-28";

/// Bound on one inbound line (4 MiB, the fleet's line bound).
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

pub type SharedStdout = Arc<Mutex<tokio::io::Stdout>>;

enum Classified {
    /// Forward the line to the service.
    Forward,
    /// A legacy `initialize` request: refuse it here, with this id.
    RefuseInitialize(Value),
    /// A notification-shaped `initialize` (no id): it opens
    /// nothing and is answered with nothing; drop it.
    Drop,
}

fn classify(line: &[u8]) -> Classified {
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return Classified::Forward;
    };
    if value.get("method").and_then(Value::as_str) != Some("initialize") {
        return Classified::Forward;
    }
    match value.get("id") {
        Some(id) if !id.is_null() => Classified::RefuseInitialize(id.clone()),
        _ => Classified::Drop,
    }
}

fn refusal_frame(id: &Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": UNSUPPORTED_PROTOCOL_VERSION,
            "message": format!(
                "unsupported protocol version: bosun speaks MCP {SUPPORTED_ERA} only; open with server/discover"
            ),
            "data": {"supported": [SUPPORTED_ERA]},
        },
    })
    .to_string()
}

/// Read stdin line by line, refusing legacy handshakes and
/// forwarding everything else to the service's side of the
/// duplex. Ends at stdin EOF; shutting the duplex write side
/// down is what ends the service (a mere drop does not signal
/// EOF while the pump still holds the read half).
pub async fn run(
    stdin: tokio::io::Stdin,
    mut client_write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    stdout: SharedStdout,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stdin);
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line).await?;
        if n == 0 {
            break;
        }
        if line.len() > MAX_LINE_BYTES {
            // Over-bound input is not forwarded; the session ends
            // rather than buffering without limit.
            break;
        }
        match classify(&line) {
            Classified::Forward => {
                client_write.write_all(&line).await?;
                if !line.ends_with(b"\n") {
                    client_write.write_all(b"\n").await?;
                }
                client_write.flush().await?;
            }
            Classified::RefuseInitialize(id) => {
                let frame = refusal_frame(&id);
                let mut out = stdout.lock().await;
                out.write_all(frame.as_bytes()).await?;
                out.write_all(b"\n").await?;
                out.flush().await?;
            }
            Classified::Drop => {}
        }
    }
    // Signal EOF to the service's read side so it can end; the
    // pump keeps the read half alive to drain final responses.
    let _ = client_write.shutdown().await;
    Ok(())
}

/// Copy service responses from the duplex back to stdout.
pub async fn pump(
    client_read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    stdout: SharedStdout,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(client_read);
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line).await?;
        if n == 0 {
            break;
        }
        let mut out = stdout.lock().await;
        out.write_all(&line).await?;
        if !line.ends_with(b"\n") {
            out.write_all(b"\n").await?;
        }
        out.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_str(s: &str) -> Classified {
        classify(s.as_bytes())
    }

    #[test]
    fn modern_requests_forward() {
        assert!(matches!(
            classify_str(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{}}"
            ),
            Classified::Forward
        ));
        assert!(matches!(
            classify_str("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}"),
            Classified::Forward
        ));
        assert!(matches!(
            classify_str("not json at all"),
            Classified::Forward
        ));
    }

    #[test]
    fn initialize_with_an_id_is_refused() {
        let frame = "{\"id\":7,\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"}}";
        match classify_str(frame) {
            Classified::RefuseInitialize(id) => assert_eq!(id, json!(7)),
            _ => panic!("initialize must be refused"),
        }
        let refusal = refusal_frame(&json!(7));
        let parsed: Value = serde_json::from_str(&refusal).expect("refusal is JSON");
        assert_eq!(parsed["error"]["code"], UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(parsed["error"]["data"]["supported"][0], SUPPORTED_ERA);
    }

    #[test]
    fn notification_shaped_initialize_is_dropped_not_answered() {
        assert!(matches!(
            classify_str("{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{}}"),
            Classified::Drop
        ));
    }
}
