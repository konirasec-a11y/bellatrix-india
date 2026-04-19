use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// JSON-RPC 2.0 request envelope (MCP over STDIO transport).
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: serde_json::Value,
    method: String,
    params: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

impl JsonRpcResponse {
    fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
    }

    fn err(id: serde_json::Value, code: i32, message: String) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: None, error: Some(JsonRpcError { code, message }) }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Bellatrix vsc_backend starting — MCP STDIO transport");

    // Project root for persisting findings (overridable via env)
    let project_root = std::env::var("BELLATRIX_PROJECT_ROOT")
        .unwrap_or_else(|_| ".".to_string());

    let router = mcp_server::router::build_default_router();
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
            Err(e) => {
                JsonRpcResponse::err(serde_json::Value::Null, -32700, format!("Parse error: {e}"))
            }
            Ok(req) => {
                if req.jsonrpc != "2.0" {
                    JsonRpcResponse::err(req.id, -32600, "Invalid Request: not JSON-RPC 2.0".into())
                } else {
                    let resp = handle_request(&router, req).await;
                    // Auto-persist findings returned by any tool call so the
                    // bellatrix_lsp can pick them up and push diagnostics to Zed.
                    if let Some(findings) = resp.result.as_ref().and_then(|r| r["findings"].as_array()) {
                        persist_findings(&project_root, findings);
                    }
                    resp
                }
            }
        };

        let mut serialized = serde_json::to_string(&response)?;
        serialized.push('\n');
        stdout.write_all(serialized.as_bytes()).await?;
        stdout.flush().await?;
    }

    Ok(())
}

async fn handle_request(
    router: &mcp_server::McpRouter,
    req: JsonRpcRequest,
) -> JsonRpcResponse {
    match req.method.as_str() {
        "ping" => JsonRpcResponse::ok(req.id, serde_json::json!({ "pong": true })),

        "tools/list" => {
            let tools = router.list_tools();
            JsonRpcResponse::ok(req.id, serde_json::json!({ "tools": tools }))
        }

        "tools/call" => {
            let params = req.params.unwrap_or(serde_json::Value::Null);
            let tool_name = match params["name"].as_str() {
                Some(n) => n.to_string(),
                None => return JsonRpcResponse::err(req.id, -32602, "Missing field: name".into()),
            };
            let tool_params = params["arguments"].clone();

            match router.dispatch(&tool_name, tool_params).await {
                Ok(result) => JsonRpcResponse::ok(req.id, result),
                Err(e) => JsonRpcResponse::err(req.id, -32000, e.to_string()),
            }
        }

        _ => JsonRpcResponse::err(req.id, -32601, format!("Method not found: {}", req.method)),
    }
}

/// Persiste findings em .bellatrix/findings.json para o bellatrix_lsp vigiar.
/// Falhas são logadas mas não propagadas — o MCP response já foi enviado.
fn persist_findings(project_root: &str, findings: &[serde_json::Value]) {
    let dir = std::path::Path::new(project_root).join(".bellatrix");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!("Cannot create .bellatrix/: {e}");
        return;
    }
    match serde_json::to_string_pretty(findings) {
        Ok(json) => {
            if let Err(e) = std::fs::write(dir.join("findings.json"), json) {
                tracing::warn!("Cannot write findings.json: {e}");
            } else {
                tracing::info!("Persisted {} findings for LSP", findings.len());
            }
        }
        Err(e) => tracing::warn!("Cannot serialize findings: {e}"),
    }
}
