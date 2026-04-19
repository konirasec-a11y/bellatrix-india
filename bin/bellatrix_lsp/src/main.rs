/// LSP adapter para o Bellatrix Zed extension.
///
/// Roda como processo nativo; o Zed conecta via STDIO usando o protocolo
/// LSP (Content-Length framing sobre JSON-RPC 2.0).
///
/// Responsabilidades:
/// 1. Responder ao handshake initialize/initialized do Zed.
/// 2. Vigiar .bellatrix/findings.json a cada 2s (polling).
/// 3. Quando o arquivo muda, enviar textDocument/publishDiagnostics para
///    cada arquivo afetado — o Zed exibe os overlays coloridos no editor.
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("bellatrix_lsp starting");

    let project_root = std::env::var("BELLATRIX_PROJECT_ROOT")
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| ".".to_string())
        });

    let findings_path = PathBuf::from(&project_root).join(".bellatrix/findings.json");
    tracing::info!("Watching findings at: {}", findings_path.display());

    let (diag_tx, mut diag_rx) = mpsc::channel::<Vec<Value>>(64);
    tokio::spawn(watch_findings(findings_path, diag_tx));

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut initialized = false;
    let mut shutdown_requested = false;

    loop {
        tokio::select! {
            result = read_message(&mut reader) => {
                match result {
                    Ok(None) => {
                        tracing::info!("stdin closed, exiting");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("read error: {e}");
                        break;
                    }
                    Ok(Some(msg)) => {
                        let method = msg["method"].as_str().unwrap_or("").to_string();
                        let id = msg.get("id").cloned();

                        match method.as_str() {
                            "initialize" => {
                                let resp = make_ok(id.unwrap(), json!({
                                    "capabilities": {
                                        // We only push diagnostics; no sync needed.
                                        "textDocumentSync": 0
                                    },
                                    "serverInfo": {
                                        "name": "bellatrix-lsp",
                                        "version": env!("CARGO_PKG_VERSION")
                                    }
                                }));
                                write_message(&mut stdout, &resp).await?;
                                initialized = true;
                                tracing::info!("LSP initialized");
                            }

                            "initialized" => {
                                // Notification — no response required.
                            }

                            "shutdown" => {
                                shutdown_requested = true;
                                write_message(&mut stdout, &make_ok(id.unwrap(), Value::Null)).await?;
                            }

                            "exit" => {
                                std::process::exit(if shutdown_requested { 0 } else { 1 });
                            }

                            // Ignore: cancel, workspace/*, $/*, etc.
                            _ => {
                                if let Some(id) = id {
                                    let err = make_err(id, -32601, format!("method not found: {method}"));
                                    write_message(&mut stdout, &err).await?;
                                }
                            }
                        }
                    }
                }
            }

            Some(notifications) = diag_rx.recv() => {
                if initialized {
                    for notif in notifications {
                        write_message(&mut stdout, &notif).await?;
                    }
                }
            }
        }
    }

    Ok(())
}

// ── File watcher ────────────────────────────────────────────────────────────

async fn watch_findings(path: PathBuf, tx: mpsc::Sender<Vec<Value>>) {
    let mut tick = interval(Duration::from_secs(2));
    let mut last_mtime: Option<SystemTime> = None;

    loop {
        tick.tick().await;

        let mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());

        let changed = match (mtime, last_mtime) {
            (Some(m), Some(l)) => m != l,
            (Some(_), None) => true,
            _ => false,
        };

        if !changed {
            continue;
        }
        last_mtime = mtime;

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("findings.json read error: {e}");
                continue;
            }
        };

        let findings: Vec<Value> = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("findings.json parse error: {e}");
                continue;
            }
        };

        tracing::info!("findings.json changed — {} findings", findings.len());
        let notifications = build_publish_diagnostics(&findings);

        if tx.send(notifications).await.is_err() {
            break; // receiver dropped
        }
    }
}

/// Agrupa findings por arquivo e gera textDocument/publishDiagnostics para cada um.
fn build_publish_diagnostics(findings: &[Value]) -> Vec<Value> {
    let mut by_file: HashMap<String, Vec<Value>> = HashMap::new();

    for f in findings {
        let file = match f["file_path"].as_str() {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => continue,
        };

        // LSP lines são 0-based; findings são 1-based.
        let line = f["line_number"].as_u64().unwrap_or(1).saturating_sub(1);
        let severity = f["severity"].as_str().unwrap_or("Info");
        let severity_code: u8 = match severity {
            "Critical" | "High" => 1,
            "Medium" => 2,
            "Low" => 3,
            _ => 4,
        };
        let title = f["title"].as_str().unwrap_or("Unknown vulnerability");
        let cwe = f["cwe"].as_str().unwrap_or("");
        let id = f["id"].as_str().unwrap_or("");

        let diag = json!({
            "range": {
                "start": { "line": line, "character": 0 },
                "end":   { "line": line, "character": 999 }
            },
            "severity": severity_code,
            "code": cwe,
            "source": "bellatrix-india",
            "message": format!("[Bellatrix] {} — {} ({})", severity, title, cwe),
            "data": { "finding_id": id, "title": title }
        });

        by_file.entry(file).or_default().push(diag);
    }

    by_file
        .into_iter()
        .map(|(uri, diagnostics)| {
            let file_uri = if uri.starts_with("file://") {
                uri
            } else {
                format!("file://{uri}")
            };
            json!({
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {
                    "uri": file_uri,
                    "diagnostics": diagnostics
                }
            })
        })
        .collect()
}

// ── LSP Content-Length transport ─────────────────────────────────────────────

async fn read_message<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<Option<Value>> {
    let mut content_length: Option<usize> = None;

    // Read headers until blank line.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None); // EOF
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Content-Length: ") {
            content_length = Some(rest.trim().parse()?);
        }
    }

    let len = content_length.ok_or_else(|| anyhow!("Missing Content-Length header"))?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(Some(serde_json::from_slice(&buf)?))
}

async fn write_message<W: AsyncWriteExt + Unpin>(writer: &mut W, msg: &Value) -> Result<()> {
    let body = serde_json::to_string(msg)?;
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    writer.write_all(header.as_bytes()).await?;
    writer.write_all(body.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

// ── JSON-RPC helpers ─────────────────────────────────────────────────────────

fn make_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn make_err(id: Value, code: i32, message: String) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: &str, file: &str, line: u64) -> Value {
        json!({
            "id": "test-id",
            "title": "SQL Injection",
            "severity": severity,
            "file_path": file,
            "line_number": line,
            "cwe": "CWE-89"
        })
    }

    #[test]
    fn critical_maps_to_error_severity() {
        let findings = vec![finding("Critical", "src/auth.php", 42)];
        let notifs = build_publish_diagnostics(&findings);
        assert_eq!(notifs.len(), 1);
        let diag = &notifs[0]["params"]["diagnostics"][0];
        assert_eq!(diag["severity"], 1);
    }

    #[test]
    fn line_number_is_zero_based() {
        let findings = vec![finding("High", "src/main.rs", 10)];
        let notifs = build_publish_diagnostics(&findings);
        let diag = &notifs[0]["params"]["diagnostics"][0];
        assert_eq!(diag["range"]["start"]["line"], 9);
    }

    #[test]
    fn groups_by_file() {
        let findings = vec![
            finding("Critical", "src/auth.php", 5),
            finding("High", "src/auth.php", 20),
            finding("Medium", "src/user.php", 7),
        ];
        let notifs = build_publish_diagnostics(&findings);
        assert_eq!(notifs.len(), 2);
        let auth_notif = notifs
            .iter()
            .find(|n| n["params"]["uri"].as_str().unwrap_or("").contains("auth.php"))
            .expect("auth.php notification missing");
        assert_eq!(auth_notif["params"]["diagnostics"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn message_includes_severity_and_cwe() {
        let findings = vec![finding("High", "src/a.php", 1)];
        let notifs = build_publish_diagnostics(&findings);
        let msg = notifs[0]["params"]["diagnostics"][0]["message"].as_str().unwrap();
        assert!(msg.contains("CWE-89"));
        assert!(msg.contains("High"));
        assert!(msg.contains("Bellatrix"));
    }

    #[test]
    fn uri_is_prefixed_with_file_scheme() {
        let findings = vec![finding("Low", "/absolute/path/file.py", 1)];
        let notifs = build_publish_diagnostics(&findings);
        let uri = notifs[0]["params"]["uri"].as_str().unwrap();
        assert!(uri.starts_with("file://"));
    }
}
