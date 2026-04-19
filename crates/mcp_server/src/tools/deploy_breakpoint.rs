use application::McpTool;
use async_trait::async_trait;
use std::path::Path;

pub struct DeployBreakpointTool;

#[async_trait]
impl McpTool for DeployBreakpointTool {
    fn name(&self) -> &str {
        "deploy_breakpoint"
    }

    fn description(&self) -> &str {
        "Writes .zed/debug.json with precise breakpoints at sink lines. \
         Optionally persists findings to .bellatrix/findings.json so the \
         bellatrix_lsp can push textDocument/publishDiagnostics overlays \
         into the Zed editor immediately."
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Source file containing the vulnerable sink"
                },
                "sink_lines": {
                    "type": "array",
                    "items": { "type": "integer" },
                    "description": "1-based line numbers of sink expressions"
                },
                "program": {
                    "type": "string",
                    "description": "Binary path for the DAP launch config (default: ${workspaceFolder}/target/debug/app)"
                },
                "project_root": {
                    "type": "string",
                    "description": "Absolute path to the project root; .zed/ and .bellatrix/ are written here"
                },
                "findings": {
                    "type": "array",
                    "description": "Full finding objects to persist for LSP diagnostic overlays"
                }
            },
            "required": ["file_path", "sink_lines"]
        })
    }

    async fn execute(&self, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let file_path = params["file_path"].as_str().unwrap_or("unknown");
        let program = params["program"]
            .as_str()
            .unwrap_or("${workspaceFolder}/target/debug/app");
        let project_root = params["project_root"].as_str().unwrap_or(".");

        let sink_lines: Vec<u64> = params["sink_lines"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
            .unwrap_or_default();

        let breakpoints: Vec<serde_json::Value> = sink_lines
            .iter()
            .map(|&line| {
                serde_json::json!({
                    "line": line,
                    "source": { "path": file_path }
                })
            })
            .collect();

        // ── Write .zed/debug.json ────────────────────────────────────────────
        let debug_config = serde_json::json!({
            "version": "0.2.0",
            "configurations": [{
                "type": "lldb",
                "request": "launch",
                "name": "Bellatrix: Debug Sink",
                "program": program,
                "stopOnEntry": false,
                "breakpoints": breakpoints
            }]
        });

        let zed_dir = Path::new(project_root).join(".zed");
        std::fs::create_dir_all(&zed_dir)
            .map_err(|e| anyhow::anyhow!("Cannot create .zed/: {e}"))?;
        let debug_path = zed_dir.join("debug.json");
        std::fs::write(&debug_path, serde_json::to_string_pretty(&debug_config)?)
            .map_err(|e| anyhow::anyhow!("Cannot write .zed/debug.json: {e}"))?;

        // ── Write .bellatrix/findings.json (feeds bellatrix_lsp) ─────────────
        let persisted = if let Some(findings) = params["findings"].as_array() {
            let dir = Path::new(project_root).join(".bellatrix");
            std::fs::create_dir_all(&dir)
                .map_err(|e| anyhow::anyhow!("Cannot create .bellatrix/: {e}"))?;
            let path = dir.join("findings.json");
            std::fs::write(&path, serde_json::to_string_pretty(findings)?)
                .map_err(|e| anyhow::anyhow!("Cannot write findings.json: {e}"))?;
            findings.len()
        } else {
            0
        };

        tracing::info!(
            file = file_path,
            breakpoints = breakpoints.len(),
            findings = persisted,
            "deploy_breakpoint: .zed/debug.json written"
        );

        Ok(serde_json::json!({
            "debug_config_written": debug_path.to_string_lossy(),
            "breakpoint_count": breakpoints.len(),
            "findings_persisted": persisted,
            "message": format!(
                "Breakpoints deployed for {}. Open Zed debugger to attach.",
                file_path
            )
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use application::McpTool;

    fn params(project_root: &str) -> serde_json::Value {
        serde_json::json!({
            "file_path": "src/auth.php",
            "sink_lines": [42, 87],
            "project_root": project_root,
            "findings": [
                {
                    "id": "f1",
                    "title": "SQL Injection",
                    "severity": "Critical",
                    "file_path": "src/auth.php",
                    "line_number": 42,
                    "cwe": "CWE-89"
                }
            ]
        })
    }

    #[tokio::test]
    async fn writes_zed_debug_json() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let tool = DeployBreakpointTool;
        tool.execute(params(root)).await.unwrap();
        let written = std::fs::read_to_string(dir.path().join(".zed/debug.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["version"], "0.2.0");
        assert_eq!(v["configurations"][0]["breakpoints"][0]["line"], 42);
    }

    #[tokio::test]
    async fn writes_findings_json() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let tool = DeployBreakpointTool;
        let result = tool.execute(params(root)).await.unwrap();
        assert_eq!(result["findings_persisted"], 1);
        let written = std::fs::read_to_string(dir.path().join(".bellatrix/findings.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v[0]["cwe"], "CWE-89");
    }

    #[tokio::test]
    async fn no_findings_param_skips_file_write() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let tool = DeployBreakpointTool;
        let p = serde_json::json!({
            "file_path": "src/a.php",
            "sink_lines": [1],
            "project_root": root
        });
        let result = tool.execute(p).await.unwrap();
        assert_eq!(result["findings_persisted"], 0);
        assert!(!dir.path().join(".bellatrix/findings.json").exists());
    }
}
